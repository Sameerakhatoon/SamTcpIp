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
// Per PLAN.md rule 1: data transfer, retransmission, congestion
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

typedef struct Tcb Tcb;
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
    GlThread        glue;
};
GLTHREAD_TO_STRUCT(glue_to_tcb, Tcb, glue);

// Register the L3 dispatcher on protocol 6. Call once at startup.
void tcp_register(void);

// Install a passive socket on (node, port). Receiver answers SYN
// with SYN-ACK; the resulting TCB ends up in ESTABLISHED after
// the third leg. Idempotent on duplicate port.
bool tcp_listen(Node* node, unsigned short port);

// Manual SYN emit for tests + ops (no full active-open FSM yet).
// Builds a SYN with our chosen ISN, computes the pseudo-csum,
// hands to L3.
void tcp_send_syn(Node* node, unsigned int dst_ip_host,
                  unsigned short src_port, unsigned short dst_port);

// Pretty-print the TCB list on this Node.
void tcp_dump(Node* node);

// ch23: send `payload` on an existing ESTABLISHED TCB to
// (dst_ip, dst_port). The 4-tuple identifies the TCB. Returns
// false if no matching ESTABLISHED TCB exists.
bool tcp_send_data(Node* node, unsigned int dst_ip_host,
                   unsigned short dst_port,
                   const char* payload, size_t payload_size);

#endif
