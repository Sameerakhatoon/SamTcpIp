#ifndef SAMTCPIP_TCP_H
#define SAMTCPIP_TCP_H

// RFC 793 TCP - just enough to handshake. ch22 ships:
//   - 20-byte TcpHdr packed.
//   - Pseudo-header checksum (same algorithm as UDP, different
//     pseudo bytes - the L4 protocol byte is 6 not 17).
//   - Per-Node TCB list (one entry per (local_ip, local_port,
//     remote_ip, remote_port) or LISTEN wildcard).
//   - FSM: CLOSED -> LISTEN -> SYN_RECEIVED -> ESTABLISHED on the
//     passive side. Active-open SYN_SENT comes in a later chapter
//     when we need outbound TCP.
//   - MSS option parsing on incoming SYN.
//   - tcp_listen(node, port) to install a passive socket.
//   - Manual tcp_send_syn helper + CLI for testing without curl.
//
// Only what we use: data transfer, retransmission, congestion
// control, RST emit, FIN orderly close all come in their own
// chapters. ch22 is just "we can agree to talk."

#include <stdbool.h>
#include <stddef.h>
#include "../graph.h"
#include "../gluethread/glthread.h"

struct IpHdr;

#define IP_PROTO_TCP        6

// Flag bits in TcpHdr.flags low 6 (RFC 793 octet 13 low 6 bits).
#define TCP_FIN      0x01
#define TCP_SYN      0x02
#define TCP_RST      0x04
#define TCP_PSH      0x08
#define TCP_ACK      0x10
#define TCP_URG      0x20

#pragma pack(push, 1)
typedef struct TcpHdr {
    unsigned short src_port;        // NBO
    unsigned short dst_port;        // NBO
    unsigned int   seq;             // NBO
    unsigned int   ack;             // NBO
    // data offset in 32-bit words is the high 4 bits of octet 12;
    // low 4 bits are reserved (zero). Store as a single byte and
    // shift on access.
    unsigned char  data_off_rsvd;
    unsigned char  flags;           // FIN/SYN/RST/PSH/ACK/URG
    unsigned short window;          // NBO
    unsigned short checksum;        // NBO; pseudo-header included
    unsigned short urg_ptr;         // NBO; unused in ch22
} TcpHdr;
#pragma pack(pop)

// FSM states. Subset of RFC 793; everything past ESTABLISHED
// arrives with later chapters.
#define TCP_CLOSED          0
#define TCP_LISTEN          1
#define TCP_SYN_RECEIVED    2
#define TCP_SYN_SENT        3       // reserved for active-open chapter
#define TCP_ESTABLISHED     4
// ch26: orderly close.
#define TCP_FIN_WAIT_1      5
#define TCP_FIN_WAIT_2      6
#define TCP_CLOSE_WAIT      7
#define TCP_LAST_ACK        8
// ch26 collapsed TIME_WAIT directly to CLOSED (no 2*MSL timer).
// TIME_WAIT for tcp_time_wait_ms, and CLOSING,
// the simultaneous close.
#define TCP_TIME_WAIT       9
#define TCP_CLOSING         10

// One out-of-order segment the receiver keeps
// until the hole before it fills.
typedef struct TcpOoo {
    unsigned int    seq;
    unsigned int    len;
    bool            fin;
    unsigned char*  data;
} TcpOoo;
#define TCP_OOO_MAX         16

typedef struct Tcb Tcb;
// ch29: per-TCB data callback. Called when ESTABLISHED + data
// arrives. Handler can call tcp_send_data + tcp_close to drive
// the conversation.
typedef void (*TcpOnData)(Tcb* tcb, const char* data, size_t len);

struct Tcb {
    Node*           node;
    unsigned int    local_ip;       // host order (matches our IP convention)
    unsigned int    remote_ip;      // host order
    unsigned short  local_port;
    unsigned short  remote_port;
    unsigned char   state;          // TCP_*
    unsigned int    iss;            // initial send seq we picked
    unsigned int    snd_nxt;        // next byte to send (relative to iss)
    unsigned int    rcv_nxt;        // next byte we expect from peer
    unsigned short  peer_mss;       // from SYN option; 536 default
    // ch40: RFC 5681 congestion control.
    //   snd_una   = oldest unACKed byte (advances on incoming ACK)
    //   cwnd      = congestion window in BYTES
    //   ssthresh  = slow-start threshold in BYTES
    // Slow start: cwnd += MSS per ACK (cwnd <= ssthresh).
    // Congestion avoidance: cwnd += max(1, MSS*MSS/cwnd) per ACK.
    // Loss event (tcp simulate-loss / future RTO): ssthresh =
    //   max(2*MSS, cwnd/2); cwnd = MSS; reset to slow start.
    unsigned int    snd_una;
    unsigned int    cwnd;
    unsigned int    ssthresh;
    // ch41: peer-advertised window from the most recent segment.
    // Send-side enforcement compares (snd_nxt - snd_una) against
    // min(cwnd, peer_window) before allowing a new emit.
    unsigned int    peer_window;
    TcpOnData       on_data;        // ch29: app-layer hook
    GlThread        glue;
    // What the kernel's sockets need (tcp.c).
    unsigned char*  sndbuf;         // queued bytes from snd_una on
    unsigned int    snd_max;        // the highest sequence sent (go-back-N
                                    // rewinds snd_nxt, not this)
    unsigned int    sndbuf_len;
    bool            fin_pending;    // close asked for: FIN after sndbuf
    bool            fin_sent;
    bool            probe;          // a zero-window probe may go
    unsigned long   rto_at;         // ms (net_now_ms), 0: no timer
    unsigned int    rto_ms;
    int             retries;
    Tcb*            listener;       // a passive child's listener
    void*           app;            // the socket (net/socket.c)
    bool            orphan;         // the socket let go: free when closed
    unsigned long   orphan_since;
    // RFC 6298 RTT estimate, one segment timed at a
    // time (Karn: never a retransmitted one).
    unsigned int    srtt8;          // SRTT * 8, ms
    unsigned int    rttvar4;        // RTTVAR * 4, ms
    bool            rtt_seen;       // a sample came: srtt8, rttvar4 valid
    bool            rtt_timing;
    unsigned int    rtt_seq;        // the ACK that ends the timed segment
    unsigned long   rtt_start;
    // RFC 5681 fast retransmit, RFC 6582 NewReno
    // recovery, RFC 3042 limited transmit.
    int             dupacks;
    bool            in_recovery;
    bool            after_rto;      // no fast retransmit below `recover`
    unsigned int    recover;        // snd_max when recovery (or an RTO) began
    // Out-of-order segments, sorted by seq.
    TcpOoo          ooo[TCP_OOO_MAX];
    int             ooo_n;
    // When TIME_WAIT ends (net_now_ms).
    unsigned long   tw_until;
};
GLTHREAD_TO_STRUCT(glue_to_tcb, Tcb, glue);

// Register the L3 dispatcher on protocol 6. Call once at startup.
void tcp_register(void);

// Install a passive socket on (node, port). Receiver answers SYN
// with SYN-ACK; the resulting TCB ends up in ESTABLISHED after
// the third leg. Idempotent on duplicate port.
bool tcp_listen(Node* node, unsigned short port);

// ch29: same as tcp_listen but also stashes an `on_data`
// callback. Child TCBs spawned from this listener inherit it.
bool tcp_listen_with_handler(Node* node, unsigned short port,
                             TcpOnData on_data);

// Manual SYN emit for tests + ops (fixed src_port chosen by
// caller). Used by tests that need deterministic 4-tuples.
void tcp_send_syn(Node* node, unsigned int dst_ip_host,
                  unsigned short src_port, unsigned short dst_port);

// ch32: real active-open. Allocates an ephemeral source port
// (Linux range 32768-60999, walks existing TCBs to avoid
// collisions), then drives the same SYN_SENT path. Returns the
// chosen local port or 0 on failure.
unsigned short tcp_connect(Node* node, unsigned int dst_ip_host,
                           unsigned short dst_port);

// Pretty-print the TCB list on this Node.
void tcp_dump(Node* node);

// ch23: send `payload` on an existing ESTABLISHED TCB to
// (dst_ip, dst_port). The 4-tuple identifies the TCB. Returns
// false if no matching ESTABLISHED TCB exists.
bool tcp_send_data(Node* node, unsigned int dst_ip_host,
                   unsigned short dst_port,
                   const char* payload, size_t payload_size);

// ch26: initiate orderly close on the (node, dst_ip, dst_port)
// TCB. Transitions ESTABLISHED -> FIN_WAIT_1 (sends FIN+ACK).
// Or CLOSE_WAIT -> LAST_ACK if we already received a FIN.
bool tcp_close(Node* node, unsigned int dst_ip_host,
               unsigned short dst_port);

// ch40: artificially trigger a loss event on the (node, dst_ip,
// dst_port) TCB. Halves cwnd into ssthresh, drops cwnd to one MSS.
// Test hook - real impls do this on RTO firing or 3-dup-ACK.
bool tcp_simulate_loss(Node* node, unsigned int dst_ip_host,
                       unsigned short dst_port);

// ch41: set the receive-window value we advertise in every
// outbound segment. Defaults to 1024.
void tcp_set_rwnd(unsigned short rwnd);

// ---- the kernel's sockets (net/socket.c) --------------------------
// Upstream drives TCP by 4-tuple from its CLI; the kernel holds the
// TCB. See tcp.c's send buffer comment for the buffer and the timer.

#define TCP_OUR_MSS         1460        // MTU 1500 - 40
#define TCP_SNDBUF_SIZE     16384
#define TCP_RTO_INIT_MS     1000        // RFC 6298, before any RTT sample
// RFC 6298 asks for at least 1 s; QEMU guests on one
// host see RTTs of a few ms, so Linux's 200 ms. The clock ticks at
// 100 Hz (G).
#define TCP_RTO_MIN_MS      200
#define TCP_RTO_MAX_MS      8000
#define TCP_CLOCK_G_MS      10
#define TCP_MAX_RETRIES     8
#define TCP_ORPHAN_MS       60000       // default of tcp_orphan_ms
// 2 * MSL scaled down for QEMU (RFC 793: 4 min).
#define TCP_TIME_WAIT_MS    2000        // default of tcp_time_wait_ms
#define TCP_TIME_WAIT_MAX   32          // more: the oldest ends early
// Boot options samos.tcp_time_wait_ms and samos.tcp_orphan_ms.
extern unsigned long tcp_time_wait_ms;
extern unsigned long tcp_orphan_ms;

// Events for the application (the kernel defines tcp_event).
enum {
    TCP_EV_ESTABLISHED,     // a handshake finished (a listener's child too)
    TCP_EV_SENT,            // queued bytes were acknowledged: room again
    TCP_EV_FIN,             // the peer closed its side
    TCP_EV_CLOSED,          // reset, timed out, or fully closed
};
void         tcp_event(Tcb* tcb, int ev);
// Room the application has for received data (the window advertised).
unsigned int tcp_app_window(Tcb* tcb);
// Whether a listener can take one more connection (its
// accept queue has room); if not, the third leg is ignored and the
// handshake is finished later, when the SYN-ACK is sent again.
bool         tcp_app_accept_room(Tcb* listener);

Tcb*   tcp_open(Node* node, unsigned int dst_ip_host, unsigned short dst_port);
Tcb*   tcp_listen_tcb(Node* node, unsigned short port, TcpOnData on_data);
// Bytes taken into the send buffer (0 when full or not open).
size_t tcp_queue_data(Tcb* tcb, const char* data, size_t len);
size_t tcp_send_room(Tcb* tcb);
void   tcp_output(Tcb* tcb);
void   tcp_close_tcb(Tcb* tcb);
// The application read; `before` was the window before it did.
void   tcp_window_update(Tcb* tcb, unsigned int before);
// The socket is gone: the TCB finishes its close and frees itself.
void   tcp_release(Tcb* tcb);
// Retransmission and cleanup, every kernel tick.
void   tcp_timer(void);
// Retransmission timeouts so far (net_info, the shell's netstat).
extern unsigned long tcp_rto_count;
// Fast retransmits (3 duplicate ACKs, NewReno partial ACKs),
// out-of-order segments kept, orphans freed by tcp_orphan_ms.
extern unsigned long tcp_fast_rtx_count;
extern unsigned long tcp_ooo_count;
extern unsigned long tcp_orphan_count;
// Feed one RTT sample (ms) to the RFC 6298 estimator;
// tcp_rto_value is the RTO it gives (no backoff).
void         tcp_rtt_sample(Tcb* tcb, unsigned int rtt_ms);
unsigned int tcp_rto_value(Tcb* tcb);

// ---- SamTcpIp: what the CLI needs in place of SamOS's sockets ------------
// The accept queue's size for the listener on (node,
// port); 0: no limit (the default). See tcp_app_accept_room.
bool tcp_set_backlog(Node* node, unsigned short port, unsigned int backlog);
// Close the listener on (node, port), as SamOS's close()
// of a listening socket does: its half-open children are reset.
bool tcp_unlisten(Node* node, unsigned short port);

#endif
