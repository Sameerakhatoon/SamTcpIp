#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../graph.h"
#include "../gluethread/glthread.h"
#include "../net.h"
#include "../utils.h"
#include "../Layer3/layer3.h"
#include "tcp.h"

// Forward declarations.
static void           tcp_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                               char* l4_payload, size_t l4_payload_size);
static unsigned short tcp_pseudo_checksum(unsigned int src_ip,
                                          unsigned int dst_ip,
                                          const void* tcp_seg,
                                          size_t tcp_seg_len);
static Tcb*           tcb_find(Node* node, unsigned int local_ip,
                               unsigned short local_port,
                               unsigned int remote_ip,
                               unsigned short remote_port);
static Tcb*           tcb_find_listener(Node* node, unsigned short local_port);
static Tcb*           tcb_alloc(Node* node);
static unsigned short tcp_parse_mss(unsigned char* opt_bytes, size_t opt_len);
static unsigned int   tcp_pick_src_ip(Node* node, unsigned int dst_ip);
static void           send_synack(Tcb* tcb, unsigned short src_mss);
static void           send_bare_ack(Tcb* tcb);
static void           send_fin_ack(Tcb* tcb);
static const char*    state_name(unsigned char s);

void                  tcp_register(void);
bool                  tcp_listen(Node* node, unsigned short port);
void                  tcp_send_syn(Node* node, unsigned int dst_ip_host,
                                   unsigned short src_port, unsigned short dst_port);
void                  tcp_dump(Node* node);

// One global TCB list. Same structure as udp_bindings.
static GlThread g_tcbs;
static bool     g_tcbs_inited = false;
static void ensure_tcbs_init(void){
    if(!g_tcbs_inited){
        init_glthread(&g_tcbs);
        g_tcbs_inited = true;
    }
}

static const char* state_name(unsigned char s){
    switch(s){
        case TCP_CLOSED:       return "CLOSED";
        case TCP_LISTEN:       return "LISTEN";
        case TCP_SYN_RECEIVED: return "SYN_RECEIVED";
        case TCP_SYN_SENT:     return "SYN_SENT";
        case TCP_ESTABLISHED:  return "ESTABLISHED";
        case TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
        case TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
        case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
        case TCP_LAST_ACK:     return "LAST_ACK";
        default:               return "?";
    }
}

// ---- TCB lookups + alloc ------------------------------------------------

static Tcb* tcb_find(Node* node, unsigned int local_ip,
                     unsigned short local_port,
                     unsigned int remote_ip,
                     unsigned short remote_port){
    ensure_tcbs_init();
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* t = glue_to_tcb(cur);
        if(t->node != node) continue;
        if(t->state == TCP_LISTEN) continue;
        if(t->local_ip == local_ip && t->local_port == local_port
           && t->remote_ip == remote_ip && t->remote_port == remote_port){
            return t;
        }
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
    return 0;
}

static Tcb* tcb_find_listener(Node* node, unsigned short local_port){
    ensure_tcbs_init();
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* t = glue_to_tcb(cur);
        if(t->node != node) continue;
        if(t->state != TCP_LISTEN) continue;
        if(t->local_port == local_port) return t;
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
    return 0;
}

static Tcb* tcb_alloc(Node* node){
    Tcb* t = calloc(1, sizeof(Tcb));
    if(!t) return 0;
    t->node     = node;
    t->state    = TCP_CLOSED;
    // RFC 793 ISN: real implementations pick (mod 2^32) over time.
    // Deterministic for the test harness; tcb_alloc id-shifted to
    // avoid clashes across concurrent TCBs.
    t->iss      = 0x1000;
    t->snd_nxt  = t->iss;
    t->peer_mss = 536;     // RFC 879 default if no MSS option.
    init_glthread(&t->glue);
    glthread_add_last(&g_tcbs, &t->glue);
    return t;
}

// ---- src_ip pick (inline, will promote when third caller appears) ------

static unsigned int tcp_pick_src_ip(Node* node, unsigned int dst_ip){
    char dst_str[16];
    unsigned int net = htonl(dst_ip);
    inet_ntop(AF_INET, &net, dst_str, 16);
    dst_str[15] = '\0';

    Interface* iface = node_get_matching_subnet_interface(node, dst_str);
    if(iface){
        unsigned int src_net = 0;
        inet_pton(AF_INET, IF_IP(iface), &src_net);
        return htonl(src_net);
    }
    if(node->node_nw_prop.is_lb_addr_config){
        unsigned int lb_net = 0;
        inet_pton(AF_INET, NODE_LO_ADDR(node), &lb_net);
        return htonl(lb_net);
    }
    return 0;
}

// ---- Pseudo-header checksum (same algorithm as UDP) --------------------

#pragma pack(push, 1)
typedef struct TcpPseudoHdr {
    unsigned int   src_ip;
    unsigned int   dst_ip;
    unsigned char  zero;
    unsigned char  protocol;
    unsigned short tcp_length;     // NBO
} TcpPseudoHdr;
#pragma pack(pop)

static unsigned short tcp_pseudo_checksum(unsigned int src_ip,
                                          unsigned int dst_ip,
                                          const void* tcp_seg,
                                          size_t tcp_seg_len){
    unsigned char scratch[sizeof(TcpPseudoHdr) + 1500] = {0};
    if(tcp_seg_len > sizeof(scratch) - sizeof(TcpPseudoHdr)){
        return 0;
    }
    TcpPseudoHdr* ph = (TcpPseudoHdr*)scratch;
    ph->src_ip     = src_ip;
    ph->dst_ip     = dst_ip;
    ph->zero       = 0;
    ph->protocol   = IP_PROTO_TCP;
    ph->tcp_length = htons((unsigned short)tcp_seg_len);
    memcpy(scratch + sizeof(TcpPseudoHdr), tcp_seg, tcp_seg_len);

    return inet_checksum(scratch, sizeof(TcpPseudoHdr) + tcp_seg_len);
}

// ---- MSS option parsing ------------------------------------------------

// Walk the TCP options area (between TcpHdr end and data_off*4).
// Return the MSS value found, or 0 if absent.
//
// RFC 793 options encoded as:
//   kind 0       END_OF_LIST  (terminator)
//   kind 1       NOP          (1 byte; padding)
//   kind 2 len 4 MSS          (length includes kind + len bytes)
//   others       skip via len
static unsigned short tcp_parse_mss(unsigned char* opt_bytes, size_t opt_len){
    size_t i = 0;
    while(i < opt_len){
        unsigned char kind = opt_bytes[i];
        if(kind == 0) return 0;            // END
        if(kind == 1){ i++; continue; }    // NOP
        if(i + 1 >= opt_len) return 0;
        unsigned char len = opt_bytes[i+1];
        if(len < 2 || i + len > opt_len) return 0;
        if(kind == 2 && len == 4){
            // 16-bit MSS in NBO at i+2..i+3.
            return ((unsigned short)opt_bytes[i+2] << 8) | opt_bytes[i+3];
        }
        i += len;
    }
    return 0;
}

// ---- Receive + FSM ------------------------------------------------------

static void send_synack(Tcb* tcb, unsigned short peer_mss){
    (void)peer_mss;     // peer_mss is stashed on the TCB; ch22 doesn't act on it.

    // Build TcpHdr + a 4-byte MSS option so the peer sees our MSS too.
    // total tcp_len = 20 (hdr) + 4 (MSS) = 24.
    unsigned char seg[64] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(tcb->local_port);
    hdr->dst_port = htons(tcb->remote_port);
    hdr->seq      = htonl(tcb->iss);
    hdr->ack      = htonl(tcb->rcv_nxt);
    hdr->data_off_rsvd = (6 << 4);     // 6 * 4 = 24 bytes header
    hdr->flags    = TCP_SYN | TCP_ACK;
    hdr->window   = htons(1024);
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;
    // MSS option (kind=2 len=4 mss=1460 default for ethernet).
    seg[20] = 2;
    seg[21] = 4;
    seg[22] = (1460 >> 8) & 0xFF;
    seg[23] = 1460 & 0xFF;

    hdr->checksum = htons(tcp_pseudo_checksum(tcb->local_ip, tcb->remote_ip,
                                              seg, 24));
    printf("TCP send : %s : SYN-ACK seq=%u ack=%u to %u.%u.%u.%u:%u\n",
           tcb->node->node_name, tcb->iss, tcb->rcv_nxt,
           (tcb->remote_ip >> 24) & 0xFF, (tcb->remote_ip >> 16) & 0xFF,
           (tcb->remote_ip >> 8)  & 0xFF,  tcb->remote_ip        & 0xFF,
           tcb->remote_port);
    demote_packet_to_layer3(tcb->node, (char*)seg, 24,
                            IP_PROTO_TCP, tcb->remote_ip);
    // Our SYN takes one sequence number.
    tcb->snd_nxt = tcb->iss + 1;
}

static void tcp_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                     char* l4_payload, size_t l4_payload_size){
    (void)iif;
    if(l4_payload_size < sizeof(TcpHdr)){
        printf("TCP recv : %s : runt segment (%zu)\n",
               node->node_name, l4_payload_size);
        return;
    }
    TcpHdr* hdr = (TcpHdr*)l4_payload;

    // Verify pseudo-csum.
    if(tcp_pseudo_checksum(ip_hdr->src_ip, ip_hdr->dst_ip,
                           hdr, l4_payload_size) != 0){
        printf("TCP recv : %s : checksum invalid (drop)\n", node->node_name);
        return;
    }

    unsigned short src_port = ntohs(hdr->src_port);
    unsigned short dst_port = ntohs(hdr->dst_port);
    unsigned int   seq      = ntohl(hdr->seq);
    unsigned int   ack      = ntohl(hdr->ack);
    unsigned char  flags    = hdr->flags;
    unsigned int   hdr_len  = (hdr->data_off_rsvd >> 4) * 4u;

    // Bounds-check the option region.
    if(hdr_len < 20 || hdr_len > l4_payload_size){
        printf("TCP recv : %s : bad data_off (%u)\n", node->node_name, hdr_len);
        return;
    }

    // Try the (4-tuple) lookup for established / synack-in-progress.
    Tcb* tcb = tcb_find(node, ip_hdr->dst_ip, dst_port,
                              ip_hdr->src_ip, src_port);
    if(!tcb){
        // Maybe a SYN to a LISTEN socket.
        if(flags & TCP_SYN){
            Tcb* lst = tcb_find_listener(node, dst_port);
            if(!lst){
                printf("TCP recv : %s : SYN to closed port %u (drop, no RST yet)\n",
                       node->node_name, dst_port);
                return;
            }
            // Spawn a child TCB in SYN_RECEIVED.
            Tcb* child = tcb_alloc(node);
            if(!child) return;
            child->local_ip    = ip_hdr->dst_ip;
            child->local_port  = dst_port;
            child->remote_ip   = ip_hdr->src_ip;
            child->remote_port = src_port;
            child->state       = TCP_SYN_RECEIVED;
            child->rcv_nxt     = seq + 1;     // peer's SYN consumes one
            // Parse MSS option if present.
            unsigned short mss = tcp_parse_mss((unsigned char*)l4_payload + sizeof(TcpHdr),
                                                hdr_len - sizeof(TcpHdr));
            if(mss > 0) child->peer_mss = mss;
            printf("TCP recv : %s : SYN seq=%u from %u.%u.%u.%u:%u (peer_mss=%u) -> SYN_RECEIVED\n",
                   node->node_name, seq,
                   (child->remote_ip >> 24) & 0xFF, (child->remote_ip >> 16) & 0xFF,
                   (child->remote_ip >> 8)  & 0xFF,  child->remote_ip        & 0xFF,
                   child->remote_port, child->peer_mss);
            send_synack(child, mss);
            return;
        }
        printf("TCP recv : %s : segment for unknown 4-tuple (drop)\n", node->node_name);
        return;
    }

    // Existing TCB. ch22 only cares about completing the handshake.
    if(tcb->state == TCP_SYN_RECEIVED && (flags & TCP_ACK) && ack == tcb->iss + 1){
        tcb->state = TCP_ESTABLISHED;
        printf("TCP recv : %s : ACK seq=%u ack=%u -> ESTABLISHED\n",
               node->node_name, seq, ack);
        return;
    }
    // Active-open: received SYN-ACK while we were in SYN_SENT.
    if(tcb->state == TCP_SYN_SENT
       && (flags & TCP_SYN) && (flags & TCP_ACK)
       && ack == tcb->snd_nxt){
        tcb->rcv_nxt = seq + 1;       // their SYN consumes one
        // Parse peer MSS option.
        unsigned short mss = tcp_parse_mss((unsigned char*)l4_payload + sizeof(TcpHdr),
                                            hdr_len - sizeof(TcpHdr));
        if(mss > 0) tcb->peer_mss = mss;
        tcb->state = TCP_ESTABLISHED;
        printf("TCP recv : %s : SYN-ACK seq=%u ack=%u (peer_mss=%u) -> ESTABLISHED\n",
               node->node_name, seq, ack, tcb->peer_mss);
        send_bare_ack(tcb);
        return;
    }

    // ch26: FIN handling. Order matters - check FIN first so the
    // associated ACK doesn't accidentally drop us into ESTABLISHED
    // logic on a FIN-only segment.
    if(flags & TCP_FIN){
        switch(tcb->state){
            case TCP_ESTABLISHED:
                // Peer initiated close. We go to CLOSE_WAIT,
                // ACK the FIN. Caller can then tcp_close to
                // send our own FIN -> LAST_ACK.
                tcb->rcv_nxt = seq + 1;     // FIN consumes one
                tcb->state   = TCP_CLOSE_WAIT;
                printf("TCP recv : %s : FIN seq=%u -> CLOSE_WAIT\n",
                       node->node_name, seq);
                send_bare_ack(tcb);
                return;
            case TCP_FIN_WAIT_1:
                // We sent FIN and they responded with FIN+ACK
                // (combined paths). Both sides closed.
                tcb->rcv_nxt = seq + 1;
                tcb->state   = TCP_CLOSED;
                printf("TCP recv : %s : FIN+ACK seq=%u -> CLOSED\n",
                       node->node_name, seq);
                send_bare_ack(tcb);
                return;
            case TCP_FIN_WAIT_2:
                tcb->rcv_nxt = seq + 1;
                tcb->state   = TCP_CLOSED;
                printf("TCP recv : %s : FIN seq=%u -> CLOSED (skipped TIME_WAIT)\n",
                       node->node_name, seq);
                send_bare_ack(tcb);
                return;
        }
    }

    // ch26: ACK that finishes FIN_WAIT_1 -> FIN_WAIT_2 (peer
    // ACKed our FIN but hasn't sent their own yet).
    if(tcb->state == TCP_FIN_WAIT_1 && (flags & TCP_ACK)
       && ack == tcb->snd_nxt){
        tcb->state = TCP_FIN_WAIT_2;
        printf("TCP recv : %s : ACK ack=%u -> FIN_WAIT_2\n",
               node->node_name, ack);
        return;
    }
    // LAST_ACK -> CLOSED on the final ACK.
    if(tcb->state == TCP_LAST_ACK && (flags & TCP_ACK)
       && ack == tcb->snd_nxt){
        tcb->state = TCP_CLOSED;
        printf("TCP recv : %s : ACK ack=%u -> CLOSED\n",
               node->node_name, ack);
        return;
    }

    // ch23: ESTABLISHED + payload -> consume + ACK.
    if(tcb->state == TCP_ESTABLISHED){
        size_t data_len = l4_payload_size - hdr_len;
        if(data_len > 0 && seq == tcb->rcv_nxt){
            char preview[33] = {0};
            size_t n = data_len < 32 ? data_len : 32;
            memcpy(preview, l4_payload + hdr_len, n);
            printf("TCP recv : %s : data seq=%u len=%zu `%s`\n",
                   node->node_name, seq, data_len, preview);
            tcb->rcv_nxt += data_len;
            send_bare_ack(tcb);
            return;
        }
        if(data_len == 0 && (flags & TCP_ACK)){
            // Pure ACK update - just bump our snd_una equivalent.
            // We don't track snd_una explicitly in ch23 (ch24 wires
            // it for rtx). Silent accept.
            return;
        }
        if(data_len > 0 && seq != tcb->rcv_nxt){
            printf("TCP recv : %s : out-of-order data seq=%u rcv_nxt=%u (drop)\n",
                   node->node_name, seq, tcb->rcv_nxt);
            return;
        }
    }

    // Otherwise: log and drop. Real FSM handling (FIN, RST)
    // arrives in later chapters.
    printf("TCP recv : %s : state=%s seq=%u ack=%u flags=0x%02x (no-op)\n",
           node->node_name, state_name(tcb->state), seq, ack, flags);
}

void tcp_register(void){
    l3_register_l4_handler(IP_PROTO_TCP, tcp_recv);
}

bool tcp_listen(Node* node, unsigned short port){
    // Don't double-register on the same port.
    if(tcb_find_listener(node, port)){
        printf("TCP listen : %s : port %u already listening\n",
               node->node_name, port);
        return false;
    }
    Tcb* t = tcb_alloc(node);
    if(!t) return false;
    t->state      = TCP_LISTEN;
    t->local_port = port;
    printf("TCP listen : %s : port %u\n", node->node_name, port);
    return true;
}

void tcp_send_syn(Node* node, unsigned int dst_ip_host,
                  unsigned short src_port, unsigned short dst_port){
    unsigned int src_ip = tcp_pick_src_ip(node, dst_ip_host);

    // Allocate a TCB in SYN_SENT so the SYN-ACK reply lands on
    // our recv path's 4-tuple lookup. Real active-open FSM with
    // ISN randomisation comes in a later chapter; ch22 just
    // wires enough to complete the handshake.
    Tcb* t = tcb_alloc(node);
    if(!t) return;
    t->state       = TCP_SYN_SENT;
    t->local_ip    = src_ip;
    t->local_port  = src_port;
    t->remote_ip   = dst_ip_host;
    t->remote_port = dst_port;
    t->iss         = 0x2000;
    t->snd_nxt     = t->iss + 1;       // SYN consumes one
    t->rcv_nxt     = 0;                // unknown until SYN-ACK

    unsigned char seg[64] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(src_port);
    hdr->dst_port = htons(dst_port);
    hdr->seq      = htonl(t->iss);
    hdr->ack      = 0;
    hdr->data_off_rsvd = (6 << 4);
    hdr->flags    = TCP_SYN;
    hdr->window   = htons(1024);
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;
    seg[20] = 2; seg[21] = 4;
    seg[22] = (1460 >> 8) & 0xFF;
    seg[23] = 1460 & 0xFF;

    hdr->checksum = htons(tcp_pseudo_checksum(src_ip, dst_ip_host, seg, 24));

    printf("TCP send : %s : SYN seq=%u to %u.%u.%u.%u:%u\n",
           node->node_name, t->iss,
           (dst_ip_host >> 24) & 0xFF, (dst_ip_host >> 16) & 0xFF,
           (dst_ip_host >> 8)  & 0xFF,  dst_ip_host        & 0xFF,
           dst_port);
    demote_packet_to_layer3(node, (char*)seg, 24,
                            IP_PROTO_TCP, dst_ip_host);
}

// ch26: send a FIN|ACK on this TCB. snd_nxt advances by 1 (FIN
// consumes a sequence number).
static void send_fin_ack(Tcb* tcb){
    unsigned char seg[32] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(tcb->local_port);
    hdr->dst_port = htons(tcb->remote_port);
    hdr->seq      = htonl(tcb->snd_nxt);
    hdr->ack      = htonl(tcb->rcv_nxt);
    hdr->data_off_rsvd = (5 << 4);
    hdr->flags    = TCP_FIN | TCP_ACK;
    hdr->window   = htons(1024);
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;

    hdr->checksum = htons(tcp_pseudo_checksum(tcb->local_ip, tcb->remote_ip,
                                              seg, 20));
    printf("TCP send : %s : FIN seq=%u ack=%u to %u.%u.%u.%u:%u\n",
           tcb->node->node_name, tcb->snd_nxt, tcb->rcv_nxt,
           (tcb->remote_ip >> 24) & 0xFF, (tcb->remote_ip >> 16) & 0xFF,
           (tcb->remote_ip >> 8)  & 0xFF,  tcb->remote_ip        & 0xFF,
           tcb->remote_port);
    demote_packet_to_layer3(tcb->node, (char*)seg, 20,
                            IP_PROTO_TCP, tcb->remote_ip);
    tcb->snd_nxt += 1;
}

// Send a bare ACK with no payload (used to complete the
// 3-way handshake from the active side).
static void send_bare_ack(Tcb* tcb){
    unsigned char seg[32] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(tcb->local_port);
    hdr->dst_port = htons(tcb->remote_port);
    hdr->seq      = htonl(tcb->snd_nxt);
    hdr->ack      = htonl(tcb->rcv_nxt);
    hdr->data_off_rsvd = (5 << 4);     // 20 bytes
    hdr->flags    = TCP_ACK;
    hdr->window   = htons(1024);
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;

    hdr->checksum = htons(tcp_pseudo_checksum(tcb->local_ip, tcb->remote_ip,
                                              seg, 20));
    printf("TCP send : %s : ACK seq=%u ack=%u to %u.%u.%u.%u:%u\n",
           tcb->node->node_name, tcb->snd_nxt, tcb->rcv_nxt,
           (tcb->remote_ip >> 24) & 0xFF, (tcb->remote_ip >> 16) & 0xFF,
           (tcb->remote_ip >> 8)  & 0xFF,  tcb->remote_ip        & 0xFF,
           tcb->remote_port);
    demote_packet_to_layer3(tcb->node, (char*)seg, 20,
                            IP_PROTO_TCP, tcb->remote_ip);
}

// ch23: send_data. Locate the ESTABLISHED TCB by remote
// (ip, port) - we ignore the local side because the test always
// has at most one outbound conn per peer. Builds PSH|ACK with
// payload, advances snd_nxt by the payload length.
bool tcp_send_data(Node* node, unsigned int dst_ip_host,
                   unsigned short dst_port,
                   const char* payload, size_t payload_size){
    ensure_tcbs_init();
    Tcb* found = 0;
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* t = glue_to_tcb(cur);
        if(t->node != node) continue;
        if(t->state != TCP_ESTABLISHED) continue;
        if(t->remote_ip == dst_ip_host && t->remote_port == dst_port){
            found = t;
            break;
        }
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
    if(!found){
        printf("TCP send : %s : no ESTABLISHED TCB to %u.%u.%u.%u:%u\n",
               node->node_name,
               (dst_ip_host >> 24) & 0xFF, (dst_ip_host >> 16) & 0xFF,
               (dst_ip_host >> 8)  & 0xFF,  dst_ip_host        & 0xFF,
               dst_port);
        return false;
    }
    if(payload_size > 150){
        printf("TCP send : %s : payload too big (%zu)\n",
               node->node_name, payload_size);
        return false;
    }
    unsigned char seg[256] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(found->local_port);
    hdr->dst_port = htons(found->remote_port);
    hdr->seq      = htonl(found->snd_nxt);
    hdr->ack      = htonl(found->rcv_nxt);
    hdr->data_off_rsvd = (5 << 4);
    hdr->flags    = TCP_PSH | TCP_ACK;
    hdr->window   = htons(1024);
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;
    memcpy(seg + 20, payload, payload_size);

    size_t seg_size = 20 + payload_size;
    hdr->checksum = htons(tcp_pseudo_checksum(found->local_ip, found->remote_ip,
                                              seg, seg_size));
    printf("TCP send : %s : data seq=%u len=%zu to %u.%u.%u.%u:%u\n",
           node->node_name, found->snd_nxt, payload_size,
           (found->remote_ip >> 24) & 0xFF, (found->remote_ip >> 16) & 0xFF,
           (found->remote_ip >> 8)  & 0xFF,  found->remote_ip        & 0xFF,
           found->remote_port);
    demote_packet_to_layer3(node, (char*)seg, seg_size,
                            IP_PROTO_TCP, dst_ip_host);
    found->snd_nxt += payload_size;
    return true;
}

bool tcp_close(Node* node, unsigned int dst_ip_host,
               unsigned short dst_port){
    ensure_tcbs_init();
    Tcb* t = 0;
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* x = glue_to_tcb(cur);
        if(x->node != node) continue;
        if(x->remote_ip == dst_ip_host && x->remote_port == dst_port){
            t = x; break;
        }
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
    if(!t){
        printf("TCP close : %s : no TCB to %u.%u.%u.%u:%u\n",
               node->node_name,
               (dst_ip_host >> 24) & 0xFF, (dst_ip_host >> 16) & 0xFF,
               (dst_ip_host >> 8)  & 0xFF,  dst_ip_host        & 0xFF,
               dst_port);
        return false;
    }
    if(t->state == TCP_ESTABLISHED){
        t->state = TCP_FIN_WAIT_1;
        printf("TCP close : %s : ESTABLISHED -> FIN_WAIT_1\n", node->node_name);
        send_fin_ack(t);
        return true;
    }
    if(t->state == TCP_CLOSE_WAIT){
        t->state = TCP_LAST_ACK;
        printf("TCP close : %s : CLOSE_WAIT -> LAST_ACK\n", node->node_name);
        send_fin_ack(t);
        return true;
    }
    printf("TCP close : %s : state=%s, no-op\n",
           node->node_name, state_name(t->state));
    return false;
}

void tcp_dump(Node* node){
    ensure_tcbs_init();
    printf("TCP TCBs : %s :\n", node->node_name);
    int idx = 0;
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* t = glue_to_tcb(cur);
        if(t->node != node) continue;
        printf("  [%d] state=%s local=%u remote=%u.%u.%u.%u:%u peer_mss=%u\n",
               idx++, state_name(t->state),
               t->local_port,
               (t->remote_ip >> 24) & 0xFF, (t->remote_ip >> 16) & 0xFF,
               (t->remote_ip >> 8)  & 0xFF,  t->remote_ip        & 0xFF,
               t->remote_port, t->peer_mss);
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
    if(idx == 0){
        printf("  (none)\n");
    }
}
