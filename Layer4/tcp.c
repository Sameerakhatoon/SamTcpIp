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
// ch27: bare RST. Used in three ways:
//   - reply to an unsolicited segment (no TCB).
//   - reply to a SYN at a port with no listener.
//   - emit before tearing down a TCB in error.
// Caller supplies the 4-tuple + the seq/ack values to fill in.
static void           send_rst_segment(Node* node,
                                       unsigned int local_ip, unsigned short local_port,
                                       unsigned int remote_ip, unsigned short remote_port,
                                       unsigned int seq, unsigned int ack,
                                       bool with_ack);
static const char*    state_name(unsigned char s);

void                  tcp_register(void);
bool                  tcp_listen(Node* node, unsigned short port);
void                  tcp_send_syn(Node* node, unsigned int dst_ip_host,
                                   unsigned short src_port, unsigned short dst_port);
unsigned short        tcp_connect(Node* node, unsigned int dst_ip_host,
                                  unsigned short dst_port);
void                  tcp_dump(Node* node);
static unsigned short tcp_alloc_ephemeral_port(Node* node, unsigned int local_ip,
                                               unsigned int remote_ip,
                                               unsigned short remote_port);

// ch41: receive-side window we advertise in every outbound
// segment. Per-process for now. CLI `run tcp-rwnd <bytes>` can
// drop this to test the peer-window send-gate.
static unsigned short g_tcp_rwnd = 1024;
void tcp_set_rwnd(unsigned short rwnd){
    g_tcp_rwnd = rwnd;
    printf("TCP rwnd : set to %u (will advertise on next segment)\n",
           g_tcp_rwnd);
}

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
    ensure_tcbs_init();           // ch27 fix: alloc was not initialising the list head
    Tcb* t = calloc(1, sizeof(Tcb));
    if(!t) return 0;
    t->node     = node;
    t->state    = TCP_CLOSED;
    // RFC 793 ISN: real implementations pick (mod 2^32) over time.
    // Deterministic for the test harness; tcb_alloc id-shifted to
    // avoid clashes across concurrent TCBs.
    t->iss      = 0x1000;
    t->snd_nxt  = t->iss;
    t->snd_una  = t->iss;
    t->peer_mss = 536;     // RFC 879 default if no MSS option.
    // ch40: RFC 5681 - initial cwnd = 1 segment (we use the SMSS
    // we've initialized, peer_mss; updated when we learn peer's
    // real MSS from a SYN/SYNACK option). ssthresh starts high
    // so we stay in slow start until something signals loss.
    t->cwnd        = t->peer_mss;
    t->ssthresh    = 65535;
    // ch41: until peer sends a real window, assume one full
    // segment of headroom (avoids zero-window deadlock on init).
    t->peer_window = t->peer_mss;
    init_glthread(&t->glue);
    glthread_add_last(&g_tcbs, &t->glue);
    return t;
}

// ---- ch30: src_ip pick now uses shared node_pick_src_ip ------

static unsigned int tcp_pick_src_ip(Node* node, unsigned int dst_ip){
    return node_pick_src_ip(node, dst_ip);
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
    // Callers pass host-order IPs (the TCB / L3 convention); the
    // pseudo-header is checksummed exactly as a real peer builds it,
    // so put the addresses in network order like the segment bytes.
    TcpPseudoHdr* ph = (TcpPseudoHdr*)scratch;
    ph->src_ip     = htonl(src_ip);
    ph->dst_ip     = htonl(dst_ip);
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
    hdr->window   = htons(g_tcp_rwnd);
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
    // Our SYN takes one sequence number; account it before it leaves.
    tcb->snd_nxt = tcb->iss + 1;
    demote_packet_to_layer3(tcb->node, (char*)seg, 24,
                            IP_PROTO_TCP, tcb->remote_ip);
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
                // ch27: SYN to a closed port -> emit RST|ACK so
                // the peer knows the port is not open. Use seq=0,
                // ack=seq+1 (we acknowledge their SYN's sequence
                // number even though we don't accept it).
                printf("TCP recv : %s : SYN to closed port %u -> RST\n",
                       node->node_name, dst_port);
                send_rst_segment(node, ip_hdr->dst_ip, dst_port,
                                 ip_hdr->src_ip, src_port,
                                 0, seq + 1, true);
                return;
            }
            // ch27 stays as a side check: don't emit anything weird
            // back if the SYN was actually a RST (defensive; SYN+RST
            // is nonsense per RFC 793 but cheap to ignore).
            if(flags & TCP_RST) return;
            // ch29: child TCB inherits the listener's on_data
            // callback (set below right after alloc).
            // Spawn a child TCB in SYN_RECEIVED.
            Tcb* child = tcb_alloc(node);
            if(!child) return;
            child->local_ip    = ip_hdr->dst_ip;
            child->local_port  = dst_port;
            child->remote_ip   = ip_hdr->src_ip;
            child->remote_port = src_port;
            child->state       = TCP_SYN_RECEIVED;
            child->rcv_nxt     = seq + 1;     // peer's SYN consumes one
            child->on_data     = lst->on_data; // ch29: inherit handler
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
        // ch27: non-SYN segment for an unknown 4-tuple. Real TCP
        // emits RST so the peer abandons its half-state. Skip if
        // the inbound is itself a RST (don't ping-pong RSTs).
        if(flags & TCP_RST){
            printf("TCP recv : %s : RST for unknown 4-tuple (drop, silent)\n",
                   node->node_name);
            return;
        }
        printf("TCP recv : %s : segment for unknown 4-tuple -> RST\n",
               node->node_name);
        unsigned int rst_seq = (flags & TCP_ACK) ? ack : 0;
        unsigned int rst_ack = (flags & TCP_ACK) ? 0   : seq + 1;
        send_rst_segment(node, ip_hdr->dst_ip, dst_port,
                         ip_hdr->src_ip, src_port,
                         rst_seq, rst_ack, !(flags & TCP_ACK));
        return;
    }

    // ch27: RST on an existing TCB -> immediate transition to CLOSED.
    // The peer has signaled abort; we MUST NOT keep using the TCB.
    if(flags & TCP_RST){
        printf("TCP recv : %s : RST received in state=%s -> CLOSED\n",
               node->node_name, state_name(tcb->state));
        tcb->state = TCP_CLOSED;
        return;
    }

    // Existing TCB. ch22 only cares about completing the handshake.
    if(tcb->state == TCP_SYN_RECEIVED && (flags & TCP_ACK) && ack == tcb->iss + 1){
        tcb->state = TCP_ESTABLISHED;
        // ch40: handshake-consumed byte is now acked.
        tcb->snd_una     = ack;
        tcb->peer_window = (unsigned int)ntohs(hdr->window);
        tcb->cwnd        = tcb->peer_mss;
        printf("TCP recv : %s : ACK seq=%u ack=%u -> ESTABLISHED\n",
               node->node_name, seq, ack);
        printf("TCP cwnd : %s : init cwnd=%u ssthresh=%u peer_win=%u\n",
               node->node_name, tcb->cwnd, tcb->ssthresh, tcb->peer_window);
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
        tcb->state       = TCP_ESTABLISHED;
        // ch40/41: SYN-ACK acked our SYN. Lock in snd_una + window.
        tcb->snd_una     = ack;
        tcb->peer_window = (unsigned int)ntohs(hdr->window);
        tcb->cwnd        = tcb->peer_mss;
        printf("TCP recv : %s : SYN-ACK seq=%u ack=%u (peer_mss=%u) -> ESTABLISHED\n",
               node->node_name, seq, ack, tcb->peer_mss);
        printf("TCP cwnd : %s : init cwnd=%u ssthresh=%u peer_win=%u\n",
               node->node_name, tcb->cwnd, tcb->ssthresh, tcb->peer_window);
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
            // ch29: dispatch to the app handler if registered.
            if(tcb->on_data){
                tcb->on_data(tcb, l4_payload + hdr_len, data_len);
            }
            return;
        }
        if(data_len == 0 && (flags & TCP_ACK)){
            // ch40: pure ACK - advance snd_una and grow cwnd if
            // the ACK actually moves the cumulative position.
            // ch41: also snapshot the peer's advertised window.
            unsigned int new_win = (unsigned int)ntohs(hdr->window);
            if(new_win != tcb->peer_window){
                tcb->peer_window = new_win;
                printf("TCP cwnd : %s : peer_window=%u\n",
                       node->node_name, tcb->peer_window);
            }
            if(ack > tcb->snd_una){
                unsigned int acked = ack - tcb->snd_una;
                tcb->snd_una = ack;
                if(tcb->cwnd <= tcb->ssthresh){
                    // Slow start: cwnd grows by 1 MSS per ACK.
                    tcb->cwnd += tcb->peer_mss;
                    printf("TCP cwnd : %s : slow-start ack=%u acked=%u cwnd=%u ssthresh=%u\n",
                           node->node_name, ack, acked,
                           tcb->cwnd, tcb->ssthresh);
                } else {
                    // Congestion avoidance: cwnd += MSS*MSS/cwnd
                    // per ACK (RFC 5681 sec 3.1).
                    unsigned int inc = (unsigned int)tcb->peer_mss
                                     * (unsigned int)tcb->peer_mss / tcb->cwnd;
                    if(inc == 0) inc = 1;
                    tcb->cwnd += inc;
                    printf("TCP cwnd : %s : cong-avoid ack=%u acked=%u cwnd=%u ssthresh=%u\n",
                           node->node_name, ack, acked,
                           tcb->cwnd, tcb->ssthresh);
                }
            }
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
    return tcp_listen_with_handler(node, port, NULL);
}

bool tcp_listen_with_handler(Node* node, unsigned short port,
                             TcpOnData on_data){
    if(tcb_find_listener(node, port)){
        printf("TCP listen : %s : port %u already listening\n",
               node->node_name, port);
        return false;
    }
    Tcb* t = tcb_alloc(node);
    if(!t) return false;
    t->state      = TCP_LISTEN;
    t->local_port = port;
    t->on_data    = on_data;
    printf("TCP listen : %s : port %u%s\n",
           node->node_name, port,
           on_data ? " (handler installed)" : "");
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
    hdr->window   = htons(g_tcp_rwnd);
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
    hdr->window   = htons(g_tcp_rwnd);
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;

    hdr->checksum = htons(tcp_pseudo_checksum(tcb->local_ip, tcb->remote_ip,
                                              seg, 20));
    printf("TCP send : %s : FIN seq=%u ack=%u to %u.%u.%u.%u:%u\n",
           tcb->node->node_name, tcb->snd_nxt, tcb->rcv_nxt,
           (tcb->remote_ip >> 24) & 0xFF, (tcb->remote_ip >> 16) & 0xFF,
           (tcb->remote_ip >> 8)  & 0xFF,  tcb->remote_ip        & 0xFF,
           tcb->remote_port);
    // Advance snd_nxt BEFORE the FIN leaves: the peer's ACK can come
    // back on the receive thread before demote returns, and it must
    // find ack == snd_nxt (else FIN_WAIT_1 never moves on).
    tcb->snd_nxt += 1;
    demote_packet_to_layer3(tcb->node, (char*)seg, 20,
                            IP_PROTO_TCP, tcb->remote_ip);
}

// ch27: build + send a bare RST. No options; 20-byte header.
static void send_rst_segment(Node* node,
                             unsigned int local_ip, unsigned short local_port,
                             unsigned int remote_ip, unsigned short remote_port,
                             unsigned int seq, unsigned int ack,
                             bool with_ack){
    unsigned char seg[32] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(local_port);
    hdr->dst_port = htons(remote_port);
    hdr->seq      = htonl(seq);
    hdr->ack      = htonl(ack);
    hdr->data_off_rsvd = (5 << 4);
    hdr->flags    = TCP_RST | (with_ack ? TCP_ACK : 0);
    hdr->window   = 0;
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;

    hdr->checksum = htons(tcp_pseudo_checksum(local_ip, remote_ip, seg, 20));
    printf("TCP send : %s : RST%s seq=%u ack=%u to %u.%u.%u.%u:%u\n",
           node->node_name, with_ack ? "|ACK" : "",
           seq, ack,
           (remote_ip >> 24) & 0xFF, (remote_ip >> 16) & 0xFF,
           (remote_ip >> 8)  & 0xFF,  remote_ip        & 0xFF,
           remote_port);
    demote_packet_to_layer3(node, (char*)seg, 20,
                            IP_PROTO_TCP, remote_ip);
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
    hdr->window   = htons(g_tcp_rwnd);
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
    if(payload_size > 1400){
        printf("TCP send : %s : payload too big (%zu)\n",
               node->node_name, payload_size);
        return false;
    }
    // ch41: send-side window enforcement.
    //
    //   allowed = min(cwnd, peer_window) - in_flight
    //
    // in_flight is bytes we've sent but not yet seen ACKed
    // (snd_nxt - snd_una). If the new chunk wouldn't fit we
    // refuse it - real TCP would queue + drain on ACK; we
    // print and drop, which is enough to prove the gate.
    unsigned int in_flight   = found->snd_nxt - found->snd_una;
    unsigned int window_room = found->cwnd < found->peer_window
                              ? found->cwnd : found->peer_window;
    if(in_flight + payload_size > window_room){
        printf("TCP send : %s : window-blocked in_flight=%u + len=%zu > min(cwnd=%u, peer_win=%u)\n",
               node->node_name, in_flight, payload_size,
               found->cwnd, found->peer_window);
        return false;
    }
    unsigned char seg[1500] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(found->local_port);
    hdr->dst_port = htons(found->remote_port);
    hdr->seq      = htonl(found->snd_nxt);
    hdr->ack      = htonl(found->rcv_nxt);
    hdr->data_off_rsvd = (5 << 4);
    hdr->flags    = TCP_PSH | TCP_ACK;
    hdr->window   = htons(g_tcp_rwnd);
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
    // Same ordering rule as send_fin_ack: account the bytes before
    // they can be ACKed.
    found->snd_nxt += payload_size;
    demote_packet_to_layer3(node, (char*)seg, seg_size,
                            IP_PROTO_TCP, dst_ip_host);
    return true;
}

// ch40: artificially trigger a loss event. RFC 5681 sec 3.1:
//   ssthresh = max(FlightSize/2, 2*SMSS)
//   cwnd     = SMSS
// Returns false if no matching TCB.
bool tcp_simulate_loss(Node* node, unsigned int dst_ip_host,
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
        printf("TCP loss : %s : no TCB to dst\n", node->node_name);
        return false;
    }
    unsigned int flight = t->snd_nxt - t->snd_una;
    unsigned int half   = flight / 2;
    unsigned int two_mss = (unsigned int)t->peer_mss * 2u;
    t->ssthresh = half > two_mss ? half : two_mss;
    t->cwnd     = t->peer_mss;
    printf("TCP cwnd : %s : LOSS flight=%u cwnd=%u ssthresh=%u\n",
           node->node_name, flight, t->cwnd, t->ssthresh);
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

// ch32: ephemeral port allocator. Linux uses 32768-60999. We
// scan that range linearly looking for a port not in use on the
// same (node, local_ip) for the same remote 4-tuple. Two TCBs
// can share a local port if their 4-tuples differ.
static unsigned short tcp_alloc_ephemeral_port(Node* node, unsigned int local_ip,
                                               unsigned int remote_ip,
                                               unsigned short remote_port){
    ensure_tcbs_init();
    static unsigned short next = 32768;
    for(int tries = 0; tries < (60999 - 32768 + 1); tries++){
        unsigned short candidate = next;
        next++;
        if(next > 60999) next = 32768;
        // Collision check: is there a TCB on (node, local_ip,
        // candidate, remote_ip, remote_port) already?
        Tcb* exists = tcb_find(node, local_ip, candidate, remote_ip, remote_port);
        if(!exists) return candidate;
    }
    return 0;     // pool exhausted
}

unsigned short tcp_connect(Node* node, unsigned int dst_ip_host,
                           unsigned short dst_port){
    unsigned int src_ip = node_pick_src_ip(node, dst_ip_host);
    if(src_ip == 0){
        printf("TCP connect : %s : no src IP for dst\n", node->node_name);
        return 0;
    }
    unsigned short src_port = tcp_alloc_ephemeral_port(node, src_ip,
                                                       dst_ip_host, dst_port);
    if(src_port == 0){
        printf("TCP connect : %s : ephemeral port pool exhausted\n",
               node->node_name);
        return 0;
    }
    printf("TCP connect : %s : src=%u.%u.%u.%u:%u -> dst=%u.%u.%u.%u:%u\n",
           node->node_name,
           (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
           (src_ip >> 8)  & 0xFF,  src_ip        & 0xFF,
           src_port,
           (dst_ip_host >> 24) & 0xFF, (dst_ip_host >> 16) & 0xFF,
           (dst_ip_host >> 8)  & 0xFF,  dst_ip_host        & 0xFF,
           dst_port);
    tcp_send_syn(node, dst_ip_host, src_port, dst_port);
    return src_port;
}

void tcp_dump(Node* node){
    ensure_tcbs_init();
    printf("TCP TCBs : %s :\n", node->node_name);
    int idx = 0;
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* t = glue_to_tcb(cur);
        if(t->node != node) continue;
        printf("  [%d] state=%s local=%u remote=%u.%u.%u.%u:%u peer_mss=%u snd_una=%u snd_nxt=%u cwnd=%u ssthresh=%u peer_win=%u\n",
               idx++, state_name(t->state),
               t->local_port,
               (t->remote_ip >> 24) & 0xFF, (t->remote_ip >> 16) & 0xFF,
               (t->remote_ip >> 8)  & 0xFF,  t->remote_ip        & 0xFF,
               t->remote_port, t->peer_mss,
               t->snd_una, t->snd_nxt, t->cwnd, t->ssthresh, t->peer_window);
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
    if(idx == 0){
        printf("  (none)\n");
    }
}
