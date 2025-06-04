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
static unsigned int   tcp_rwnd(Tcb* tcb);
static void          tcp_arm(Tcb* tcb);
static void          send_syn(Tcb* t);

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
        if(t->state == TCP_CLOSED) continue;    // a dead TCB is no match
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

// SamTcpIp: the next ISS of an active (SYN) or passive
// (SYN-ACK) open. See tcb_alloc.
static unsigned int tcp_next_iss(bool active){
    static unsigned int next_active  = 0x2000;
    static unsigned int next_passive = 0x1000;
    unsigned int* n = active ? &next_active : &next_passive;
    unsigned int iss = *n;
    *n += 0x10000;
    return iss;
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
    // A new ISS per connection, 64 Ki apart, so a 4-tuple
    // used again soon (a fast reconnect) does not meet its old segments.
    // SamTcpIp: two sequences, set when the SYN or SYN-ACK is built
    // (tcp_next_iss), so the first active open still starts at ch22's
    // 0x2000 and the first passive one at 0x1000, as the course's tests
    // and chapters show. SamOS numbers every TCB from one sequence.
    t->iss      = 0x1000;
    t->rto_ms   = TCP_RTO_INIT_MS;
    t->snd_nxt  = t->iss;
    t->snd_una  = t->iss;
    t->snd_max  = t->iss;
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

// ---- send buffer, output, retransmission -----------------
//
// Upstream sends each tcp_send_data call as one segment, right away,
// and forgets it: no copy is kept, so nothing can be retransmitted,
// and a call that does not fit the window is refused. The kernel's
// sockets need a byte stream that survives loss, so each TCB keeps
// what the application queued, from snd_una on, in `sndbuf`:
// [snd_una, snd_nxt) is in flight, the rest waits for the window.
// tcp_output sends what min(cwnd, peer_window) (ch40, ch41) allows,
// in segments of at most the peer's MSS, and the FIN once the buffer
// is empty. The retransmission timer (RFC 6298's 1 s initial RTO,
// doubled per expiry up to TCP_RTO_MAX_MS) runs on the kernel tick
// (tcp_timer): on expiry it treats the loss as ch40's loss event
// (ssthresh = max(flight / 2, 2 * MSS), cwnd = MSS) and goes back to
// snd_una (go-back-N, as there is no SACK); a SYN or SYN-ACK is sent
// again. TCP_MAX_RETRIES expiries in a row abort the connection.

#define SEQ_LT(a, b)    ((int)((a) - (b)) < 0)
#define SEQ_LEQ(a, b)   ((int)((a) - (b)) <= 0)

// The window we advertise: the application's room (the socket's
// receive buffer), ch41's g_tcp_rwnd for a TCB without one.
static unsigned int tcp_rwnd(Tcb* tcb){
    unsigned int w = tcb->app || tcb->listener ? tcp_app_window(tcb) : g_tcp_rwnd;
    return w > 65535 ? 65535 : w;
}

static unsigned int tcp_mss(Tcb* tcb){
    return tcb->peer_mss < TCP_OUR_MSS ? tcb->peer_mss : TCP_OUR_MSS;
}

// snd_nxt moved on: remember the highest sequence that went out, which
// an ACK may cover even after the retransmission timer rewound snd_nxt.
static void tcp_sent_upto(Tcb* tcb){
    if(SEQ_LT(tcb->snd_max, tcb->snd_nxt)){
        tcb->snd_max = tcb->snd_nxt;
    }
}

static void tcp_arm(Tcb* tcb){
    tcb->rto_at = net_now_ms() + tcb->rto_ms;
}

// ch40: RFC 5681 loss event, as tcp_simulate_loss does it.
static void tcp_loss_event(Tcb* t){
    unsigned int flight  = t->snd_max - t->snd_una;
    unsigned int half    = flight / 2;
    unsigned int two_mss = (unsigned int)t->peer_mss * 2u;
    t->ssthresh = half > two_mss ? half : two_mss;
    t->cwnd     = t->peer_mss;
    printf("TCP cwnd : %s : LOSS flight=%u cwnd=%u ssthresh=%u\n",
           t->node->node_name, flight, t->cwnd, t->ssthresh);
}

// One data segment (ch23's PSH|ACK), `len` bytes from the send buffer
// at sequence `seq`.
static void tcp_emit_data(Tcb* tcb, unsigned int seq, const unsigned char* data, size_t len){
    unsigned char seg[20 + TCP_OUR_MSS] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(tcb->local_port);
    hdr->dst_port = htons(tcb->remote_port);
    hdr->seq      = htonl(seq);
    hdr->ack      = htonl(tcb->rcv_nxt);
    hdr->data_off_rsvd = (5 << 4);
    hdr->flags    = TCP_PSH | TCP_ACK;
    hdr->window   = htons(tcp_rwnd(tcb));
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;
    memcpy(seg + 20, data, len);
    hdr->checksum = htons(tcp_pseudo_checksum(tcb->local_ip, tcb->remote_ip, seg, 20 + len));
    printf("TCP send : %s : data seq=%u len=%zu to %u.%u.%u.%u:%u\n",
           tcb->node->node_name, seq, len,
           (tcb->remote_ip >> 24) & 0xFF, (tcb->remote_ip >> 16) & 0xFF,
           (tcb->remote_ip >> 8)  & 0xFF,  tcb->remote_ip        & 0xFF,
           tcb->remote_port);
    demote_packet_to_layer3(tcb->node, (char*)seg, 20 + len, IP_PROTO_TCP, tcb->remote_ip);
}

void tcp_output(Tcb* tcb){
    if(tcb->state != TCP_ESTABLISHED && tcb->state != TCP_CLOSE_WAIT
       && tcb->state != TCP_FIN_WAIT_1 && tcb->state != TCP_LAST_ACK){
        return;
    }
    while(!tcb->fin_sent){
        unsigned int off = tcb->snd_nxt - tcb->snd_una;
        if(off >= tcb->sndbuf_len){
            break;
        }
        unsigned int window = tcb->cwnd < tcb->peer_window ? tcb->cwnd : tcb->peer_window;
        if(window == 0 && off == 0 && tcb->probe){
            window = 1;                     // zero-window probe
        }
        if(off >= window){
            break;
        }
        unsigned int len = tcb->sndbuf_len - off;
        if(len > window - off) len = window - off;
        if(len > tcp_mss(tcb)) len = tcp_mss(tcb);
        unsigned int seq = tcb->snd_nxt;
        tcb->snd_nxt += len;                // ch43: advance before the send
        tcp_sent_upto(tcb);
        tcp_emit_data(tcb, seq, tcb->sndbuf + off, len);
    }
    tcb->probe = false;
    if(tcb->fin_pending && !tcb->fin_sent && tcb->snd_nxt - tcb->snd_una == tcb->sndbuf_len){
        tcb->fin_sent = true;
        send_fin_ack(tcb);
    }
    if(!tcb->rto_at && (tcb->snd_nxt != tcb->snd_una || tcb->sndbuf_len > 0)){
        tcp_arm(tcb);
    }
}

// The ACK field of a synchronized-state segment: ch40's cwnd growth
// (moved here from the pure-ACK branch), ch41's peer window, and the
// acknowledged bytes leave the send buffer.
static void tcp_ack_received(Tcb* tcb, unsigned int ack, unsigned int window){
    if(window != tcb->peer_window){
        tcb->peer_window = window;
        printf("TCP cwnd : %s : peer_window=%u\n",
               tcb->node->node_name, tcb->peer_window);
    }
    // Up to snd_max, not snd_nxt. After a timeout
    // snd_nxt is back at snd_una, and the peer, which kept the segments
    // after the lost one, acknowledges all of them at once.
    if(!SEQ_LT(tcb->snd_una, ack) || !SEQ_LEQ(ack, tcb->snd_max)){
        return;
    }
    unsigned int acked = ack - tcb->snd_una;
    unsigned int data  = acked < tcb->sndbuf_len ? acked : tcb->sndbuf_len;
    if(data){                               // no buffer before the first send
        memmove(tcb->sndbuf, tcb->sndbuf + data, tcb->sndbuf_len - data);
    }
    tcb->sndbuf_len -= data;
    tcb->snd_una = ack;
    if(SEQ_LT(tcb->snd_nxt, ack)){
        tcb->snd_nxt = ack;
    }
    if(acked > data && tcb->fin_pending){
        tcb->fin_sent = true;               // the ACK covers our FIN
    }
    if(tcb->cwnd <= tcb->ssthresh){
        // Slow start: cwnd grows by 1 MSS per ACK.
        tcb->cwnd += tcb->peer_mss;
        printf("TCP cwnd : %s : slow-start ack=%u acked=%u cwnd=%u ssthresh=%u\n",
               tcb->node->node_name, ack, acked, tcb->cwnd, tcb->ssthresh);
    } else {
        // Congestion avoidance: cwnd += MSS*MSS/cwnd
        // per ACK (RFC 5681 sec 3.1).
        unsigned int inc = (unsigned int)tcb->peer_mss
                         * (unsigned int)tcb->peer_mss / tcb->cwnd;
        if(inc == 0) inc = 1;
        tcb->cwnd += inc;
        printf("TCP cwnd : %s : cong-avoid ack=%u acked=%u cwnd=%u ssthresh=%u\n",
               tcb->node->node_name, ack, acked, tcb->cwnd, tcb->ssthresh);
    }
    tcb->retries = 0;
    tcb->rto_ms  = TCP_RTO_INIT_MS;
    tcb->rto_at  = 0;
    if(tcb->snd_nxt != tcb->snd_una){
        tcp_arm(tcb);
    }
    if(data){
        tcp_event(tcb, TCP_EV_SENT);
    }
}

size_t tcp_queue_data(Tcb* tcb, const char* data, size_t len){
    if(tcb->fin_pending || (tcb->state != TCP_ESTABLISHED && tcb->state != TCP_CLOSE_WAIT)){
        return 0;
    }
    if(!tcb->sndbuf){
        tcb->sndbuf = malloc(TCP_SNDBUF_SIZE);
        if(!tcb->sndbuf){
            return 0;
        }
    }
    size_t room = TCP_SNDBUF_SIZE - tcb->sndbuf_len;
    if(len > room) len = room;
    memcpy(tcb->sndbuf + tcb->sndbuf_len, data, len);
    tcb->sndbuf_len += (unsigned int)len;
    tcp_output(tcb);
    return len;
}

size_t tcp_send_room(Tcb* tcb){
    return TCP_SNDBUF_SIZE - tcb->sndbuf_len;
}

// The application took data: tell the peer when the window it last
// saw was smaller than a segment (a window update).
void tcp_window_update(Tcb* tcb, unsigned int before){
    if(before < tcp_mss(tcb) && tcp_rwnd(tcb) >= tcp_mss(tcb)
       && (tcb->state == TCP_ESTABLISHED || tcb->state == TCP_FIN_WAIT_1 || tcb->state == TCP_FIN_WAIT_2)){
        send_bare_ack(tcb);
    }
}

unsigned long tcp_rto_count;

void tcp_timer(void){
    ensure_tcbs_init();
    unsigned long now = net_now_ms();
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* t = glue_to_tcb(cur);
        // A TCB its socket let go of: freed once closed, or after
        // TCP_ORPHAN_MS (no TIME_WAIT, a peer that never closes).
        if(t->orphan && (t->state == TCP_CLOSED || now - t->orphan_since > TCP_ORPHAN_MS)){
            remove_glthread(&t->glue);
            free(t->sndbuf);
            free(t);
            continue;
        }
        if(!t->rto_at || now < t->rto_at){
            continue;
        }
        if(++t->retries > TCP_MAX_RETRIES){
            printf("TCP timer : %s : %u retransmissions, state=%s -> CLOSED\n",
                   t->node->node_name, TCP_MAX_RETRIES, state_name(t->state));
            send_rst_segment(t->node, t->local_ip, t->local_port, t->remote_ip, t->remote_port,
                             t->snd_nxt, t->rcv_nxt, true);
            t->state  = TCP_CLOSED;
            t->rto_at = 0;
            tcp_event(t, TCP_EV_CLOSED);
            continue;
        }
        t->rto_ms = t->rto_ms * 2 > TCP_RTO_MAX_MS ? TCP_RTO_MAX_MS : t->rto_ms * 2;
        t->rto_at = 0;
        tcp_rto_count++;
        printf("TCP timer : %s : RTO state=%s snd_una=%u snd_nxt=%u try %d\n",
               t->node->node_name, state_name(t->state), t->snd_una, t->snd_nxt, t->retries);
        if(t->state == TCP_SYN_SENT){
            send_syn(t);
            tcp_arm(t);
        } else if(t->state == TCP_SYN_RECEIVED){
            send_synack(t, 0);
            tcp_arm(t);
        } else {
            if(t->snd_max != t->snd_una){
                tcp_loss_event(t);
            }
            t->snd_nxt  = t->snd_una;
            t->fin_sent = false;
            t->probe    = t->peer_window == 0;
            tcp_output(t);
        }
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
}

// The kernel's sockets hold a TCB, not a 4-tuple.
Tcb* tcp_open(Node* node, unsigned int dst_ip_host, unsigned short dst_port){
    unsigned short port = tcp_connect(node, dst_ip_host, dst_port);
    return port ? tcb_find(node, node_pick_src_ip(node, dst_ip_host), port, dst_ip_host, dst_port) : 0;
}

Tcb* tcp_listen_tcb(Node* node, unsigned short port, TcpOnData on_data){
    return tcp_listen_with_handler(node, port, on_data) ? tcb_find_listener(node, port) : 0;
}

// A listener going away. Its passive children point at
// it (Tcb.listener) and it is freed on the next tick: forget it in every
// child, and reset the ones no socket has taken yet (still in
// SYN_RECEIVED), which nobody would ever accept or free.
static void tcp_drop_children(Tcb* l){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* c = glue_to_tcb(cur);
        if(c->listener != l) continue;
        c->listener = 0;
        if(c->app || c->orphan) continue;
        if(c->state != TCP_CLOSED){
            send_rst_segment(c->node, c->local_ip, c->local_port, c->remote_ip, c->remote_port,
                             c->snd_nxt, c->rcv_nxt, true);
            c->state  = TCP_CLOSED;
            c->rto_at = 0;
        }
        tcp_release(c);
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
}

void tcp_close_tcb(Tcb* t){
    if(t->state == TCP_LISTEN){
        tcp_drop_children(t);
    }
    if(t->state == TCP_ESTABLISHED){
        t->state = TCP_FIN_WAIT_1;
        printf("TCP close : %s : ESTABLISHED -> FIN_WAIT_1\n", t->node->node_name);
    } else if(t->state == TCP_CLOSE_WAIT){
        t->state = TCP_LAST_ACK;
        printf("TCP close : %s : CLOSE_WAIT -> LAST_ACK\n", t->node->node_name);
    } else if(t->state == TCP_LISTEN || t->state == TCP_SYN_SENT || t->state == TCP_SYN_RECEIVED){
        t->state  = TCP_CLOSED;
        t->rto_at = 0;
        return;
    } else {
        return;
    }
    t->fin_pending = true;
    tcp_output(t);
}

void tcp_release(Tcb* t){
    t->app          = 0;
    t->orphan       = true;
    t->orphan_since = net_now_ms();
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
    hdr->window   = htons(tcp_rwnd(tcb));
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
    tcp_sent_upto(tcb);
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
            child->listener    = lst;          // whose accept queue
            child->iss         = tcp_next_iss(false);
            child->snd_una     = child->iss;
            child->snd_nxt     = child->iss;
            child->snd_max     = child->iss;
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
            tcp_arm(child);                    // SYN-ACK retransmission
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
        tcb->state  = TCP_CLOSED;
        tcb->rto_at = 0;
        tcp_event(tcb, TCP_EV_CLOSED);
        return;
    }

    // Existing TCB. ch22 only cares about completing the handshake.
    // The third leg may carry data (and a FIN); it goes
    // on to the synchronized-state handling below instead of being
    // dropped by a return.
    // Not while the listener's accept queue is full; the
    // child stays in SYN_RECEIVED, its timer sends the SYN-ACK again and
    // the peer's ACK of that (or its data) completes the handshake then.
    if(tcb->state == TCP_SYN_RECEIVED && (flags & TCP_ACK) && ack == tcb->iss + 1
       && tcb->listener && !tcp_app_accept_room(tcb->listener)){
        printf("TCP recv : %s : accept queue full, third leg from port %u ignored\n",
               node->node_name, tcb->remote_port);
    } else if(tcb->state == TCP_SYN_RECEIVED && (flags & TCP_ACK) && ack == tcb->iss + 1){
        tcb->state = TCP_ESTABLISHED;
        // ch40: handshake-consumed byte is now acked.
        tcb->snd_una     = ack;
        tcb->peer_window = (unsigned int)ntohs(hdr->window);
        tcb->cwnd        = tcb->peer_mss;
        tcb->rto_at      = 0;
        tcb->retries     = 0;
        printf("TCP recv : %s : ACK seq=%u ack=%u -> ESTABLISHED\n",
               node->node_name, seq, ack);
        printf("TCP cwnd : %s : init cwnd=%u ssthresh=%u peer_win=%u\n",
               node->node_name, tcb->cwnd, tcb->ssthresh, tcb->peer_window);
        tcp_event(tcb, TCP_EV_ESTABLISHED);
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
        tcb->rto_at      = 0;
        tcb->retries     = 0;
        printf("TCP recv : %s : SYN-ACK seq=%u ack=%u (peer_mss=%u) -> ESTABLISHED\n",
               node->node_name, seq, ack, tcb->peer_mss);
        printf("TCP cwnd : %s : init cwnd=%u ssthresh=%u peer_win=%u\n",
               node->node_name, tcb->cwnd, tcb->ssthresh, tcb->peer_window);
        send_bare_ack(tcb);
        tcp_event(tcb, TCP_EV_ESTABLISHED);
        return;
    }
    if(tcb->state == TCP_SYN_SENT || tcb->state == TCP_SYN_RECEIVED || tcb->state == TCP_CLOSED){
        printf("TCP recv : %s : state=%s seq=%u ack=%u flags=0x%02x (no-op)\n",
               node->node_name, state_name(tcb->state), seq, ack, flags);
        return;
    }
    // A SYN in a synchronized state is the peer's
    // handshake again (its SYN-ACK resent because our third leg was not
    // taken): drop it and ACK what we expect (RFC 793, an unacceptable
    // segment), which lets the peer finish.
    if(flags & TCP_SYN){
        printf("TCP recv : %s : SYN seq=%u in state=%s -> ACK\n",
               node->node_name, seq, state_name(tcb->state));
        send_bare_ack(tcb);
        return;
    }

    // The synchronized states, in RFC 793's order:
    // the ACK field first (ch40's cwnd growth and ch41's peer window,
    // now for every segment that carries an ACK, not only a pure
    // one), then the data (ch23), then the FIN (ch26). Upstream
    // checked the FIN first and so lost data riding on a FIN.
    size_t data_len = l4_payload_size - hdr_len;
    if(flags & TCP_ACK){
        tcp_ack_received(tcb, ack, (unsigned int)ntohs(hdr->window));
    }

    // ch26: ACK that finishes FIN_WAIT_1 -> FIN_WAIT_2 (peer
    // ACKed our FIN but hasn't sent their own yet).
    if(tcb->state == TCP_FIN_WAIT_1 && tcb->fin_sent && (flags & TCP_ACK)
       && ack == tcb->snd_nxt){
        tcb->state = TCP_FIN_WAIT_2;
        printf("TCP recv : %s : ACK ack=%u -> FIN_WAIT_2\n",
               node->node_name, ack);
    }
    // LAST_ACK -> CLOSED on the final ACK.
    if(tcb->state == TCP_LAST_ACK && tcb->fin_sent && (flags & TCP_ACK)
       && ack == tcb->snd_nxt){
        tcb->state = TCP_CLOSED;
        printf("TCP recv : %s : ACK ack=%u -> CLOSED\n",
               node->node_name, ack);
        tcp_event(tcb, TCP_EV_CLOSED);
        return;
    }

    bool receiving = tcb->state == TCP_ESTABLISHED || tcb->state == TCP_FIN_WAIT_1
                  || tcb->state == TCP_FIN_WAIT_2;
    if((data_len > 0 || (flags & TCP_FIN)) && seq != tcb->rcv_nxt){
        // Out of order or a retransmission of what we
        // have: drop it, but ACK what we expect, so a lost ACK is
        // repaired and the peer's retransmission timer stops.
        printf("TCP recv : %s : out-of-order data seq=%u rcv_nxt=%u (drop)\n",
               node->node_name, seq, tcb->rcv_nxt);
        send_bare_ack(tcb);
        return;
    }

    // ch23: payload -> consume + ACK. No more than the
    // application has room for (the window we advertised).
    size_t take = receiving ? data_len : 0;
    if(take > 0){
        unsigned int room = tcp_rwnd(tcb);
        if(take > room) take = room;
        char preview[33] = {0};
        size_t n = take < 32 ? take : 32;
        memcpy(preview, l4_payload + hdr_len, n);
        printf("TCP recv : %s : data seq=%u len=%zu `%s`\n",
               node->node_name, seq, take, preview);
        tcb->rcv_nxt += take;
        // ch29: dispatch to the app handler if registered.
        if(tcb->on_data){
            tcb->on_data(tcb, l4_payload + hdr_len, take);
        }
    }

    // ch26: FIN handling, once everything before it is in.
    if((flags & TCP_FIN) && take == data_len){
        switch(tcb->state){
            case TCP_ESTABLISHED:
                // Peer initiated close. We go to CLOSE_WAIT,
                // ACK the FIN. Caller can then tcp_close to
                // send our own FIN -> LAST_ACK.
                tcb->rcv_nxt += 1;          // FIN consumes one
                tcb->state   = TCP_CLOSE_WAIT;
                printf("TCP recv : %s : FIN seq=%u -> CLOSE_WAIT\n",
                       node->node_name, seq);
                send_bare_ack(tcb);
                tcp_event(tcb, TCP_EV_FIN);
                return;
            case TCP_FIN_WAIT_1:
                // We sent FIN and they responded with FIN+ACK
                // (combined paths). Both sides closed.
                tcb->rcv_nxt += 1;
                tcb->state   = TCP_CLOSED;
                tcb->rto_at  = 0;
                printf("TCP recv : %s : FIN+ACK seq=%u -> CLOSED\n",
                       node->node_name, seq);
                send_bare_ack(tcb);
                tcp_event(tcb, TCP_EV_CLOSED);
                return;
            case TCP_FIN_WAIT_2:
                tcb->rcv_nxt += 1;
                tcb->state   = TCP_CLOSED;
                printf("TCP recv : %s : FIN seq=%u -> CLOSED (skipped TIME_WAIT)\n",
                       node->node_name, seq);
                send_bare_ack(tcb);
                tcp_event(tcb, TCP_EV_CLOSED);
                return;
        }
    }
    if(data_len > 0){
        send_bare_ack(tcb);
    }
    tcp_output(tcb);
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

// The SYN of ch22's active open, on its own so the
// retransmission timer can send it again.
static void send_syn(Tcb* t){
    unsigned char seg[64] = {0};
    TcpHdr* hdr = (TcpHdr*)seg;
    hdr->src_port = htons(t->local_port);
    hdr->dst_port = htons(t->remote_port);
    hdr->seq      = htonl(t->iss);
    hdr->ack      = 0;
    hdr->data_off_rsvd = (6 << 4);
    hdr->flags    = TCP_SYN;
    hdr->window   = htons(tcp_rwnd(t));
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;
    seg[20] = 2; seg[21] = 4;
    seg[22] = (TCP_OUR_MSS >> 8) & 0xFF;
    seg[23] = TCP_OUR_MSS & 0xFF;

    hdr->checksum = htons(tcp_pseudo_checksum(t->local_ip, t->remote_ip, seg, 24));

    printf("TCP send : %s : SYN seq=%u to %u.%u.%u.%u:%u\n",
           t->node->node_name, t->iss,
           (t->remote_ip >> 24) & 0xFF, (t->remote_ip >> 16) & 0xFF,
           (t->remote_ip >> 8)  & 0xFF,  t->remote_ip        & 0xFF,
           t->remote_port);
    demote_packet_to_layer3(t->node, (char*)seg, 24,
                            IP_PROTO_TCP, t->remote_ip);
}

void tcp_send_syn(Node* node, unsigned int dst_ip_host,
                  unsigned short src_port, unsigned short dst_port){
    unsigned int src_ip = tcp_pick_src_ip(node, dst_ip_host);

    // Allocate a TCB in SYN_SENT so the SYN-ACK reply lands on
    // our recv path's 4-tuple lookup. A fresh ISS (
    // tcp_next_iss), the SYN goes again on the retransmission timer.
    Tcb* t = tcb_alloc(node);
    if(!t) return;
    t->iss         = tcp_next_iss(true);
    t->state       = TCP_SYN_SENT;
    t->local_ip    = src_ip;
    t->local_port  = src_port;
    t->remote_ip   = dst_ip_host;
    t->remote_port = dst_port;
    t->snd_una     = t->iss;
    t->snd_nxt     = t->iss + 1;       // SYN consumes one
    t->snd_max     = t->snd_nxt;
    t->rcv_nxt     = 0;                // unknown until SYN-ACK
    send_syn(t);
    tcp_arm(t);
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
    hdr->window   = htons(tcp_rwnd(tcb));
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
    tcp_sent_upto(tcb);
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
    hdr->window   = htons(tcp_rwnd(tcb));
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
    // Into the send buffer; tcp_output sends what the
    // window allows (ch41's gate) and the rest when ACKs open it.
    // SamTcpIp: ch41's log line stays, now for a send that waits.
    unsigned int in_flight   = found->snd_nxt - found->snd_una;
    unsigned int window_room = found->cwnd < found->peer_window
                             ? found->cwnd : found->peer_window;
    if(in_flight + payload_size > window_room){
        printf("TCP send : %s : window-blocked in_flight=%u + len=%zu > min(cwnd=%u, peer_win=%u), queued\n",
               node->node_name, in_flight, payload_size,
               found->cwnd, found->peer_window);
    }
    return tcp_queue_data(found, payload, payload_size) == payload_size;
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
    tcp_loss_event(t);         // shared with the RTO
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
    // The FIN goes after the queued data (tcp_output).
    if(t->state != TCP_ESTABLISHED && t->state != TCP_CLOSE_WAIT){
        printf("TCP close : %s : state=%s, no-op\n",
               node->node_name, state_name(t->state));
        return false;
    }
    tcp_close_tcb(t);
    return true;
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

// ---- SamTcpIp: the application side SamOS's sockets provide -------------
//
// In SamOS net/socket.c defines these: tcp_event wakes the socket's
// waiters, tcp_app_window is the room left in its receive buffer. The
// simulator has no sockets; the CLI drives TCBs by 4-tuple and the
// ch29 on_data handler takes received bytes at once, so the window is
// ch41's g_tcp_rwnd and an event has nobody to wake.
//
// One event matters: a passive child whose handshake finished is, in
// SamOS, a socket on the listener's accept queue (Tcb.app set). Here
// the CLI owns it from then on (by 4-tuple), so app points at the TCB
// itself: tcp_drop_children then resets only the half-open
// children, as SamOS does, and leaves the established ones alone.
void tcp_event(Tcb* tcb, int ev){
    if(ev == TCP_EV_ESTABLISHED && tcb->listener && !tcb->app){
        tcb->app = tcb;
    }
}

unsigned int tcp_app_window(Tcb* tcb){
    (void)tcb;
    return g_tcp_rwnd;
}

// SamOS asks the listening socket whether its accept
// queue (backlog) has room. Here the queue is the listener's children
// still in ESTABLISHED or CLOSE_WAIT (nothing accept()s them; the CLI
// closing one makes room), against a backlog set per (node, port) with
// `config node X tcp-backlog <port> <n>`; no backlog set: always room.
#define TCP_BACKLOG_SLOTS 8
static struct { Node* node; unsigned short port; unsigned int backlog; } g_backlog[TCP_BACKLOG_SLOTS];

bool tcp_set_backlog(Node* node, unsigned short port, unsigned int backlog){
    int free_slot = -1;
    for(int i = 0; i < TCP_BACKLOG_SLOTS; i++){
        if(g_backlog[i].node == node && g_backlog[i].port == port){
            free_slot = i;
            break;
        }
        if(!g_backlog[i].node && free_slot < 0){
            free_slot = i;
        }
    }
    if(free_slot < 0){
        return false;
    }
    g_backlog[free_slot].node    = backlog ? node : 0;
    g_backlog[free_slot].port    = port;
    g_backlog[free_slot].backlog = backlog;
    printf("TCP listen : %s : port %u backlog %u\n", node->node_name, port, backlog);
    return true;
}

bool tcp_app_accept_room(Tcb* listener){
    unsigned int backlog = 0;
    for(int i = 0; i < TCP_BACKLOG_SLOTS; i++){
        if(g_backlog[i].node == listener->node && g_backlog[i].port == listener->local_port){
            backlog = g_backlog[i].backlog;
        }
    }
    if(!backlog){
        return true;
    }
    unsigned int queued = 0;
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_tcbs, cur){
        Tcb* c = glue_to_tcb(cur);
        if(c->listener == listener
           && (c->state == TCP_ESTABLISHED || c->state == TCP_CLOSE_WAIT)){
            queued++;
        }
    } ITERATE_GLTHREAD_END(&g_tcbs, cur);
    return queued < backlog;
}

// `run node X tcp-unlisten <port>`, SamOS's close() of
// a listening socket.
bool tcp_unlisten(Node* node, unsigned short port){
    Tcb* l = tcb_find_listener(node, port);
    if(!l){
        printf("TCP close : %s : no listener on port %u\n", node->node_name, port);
        return false;
    }
    printf("TCP close : %s : listener on port %u closed\n", node->node_name, port);
    tcp_close_tcb(l);
    return true;
}
