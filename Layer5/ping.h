#ifndef SAMTCPIP_PING_H
#define SAMTCPIP_PING_H

// Simple ping application sitting above L4. Sends a `PingMsg` as
// the IP payload with a protocol number distinct from IP_HDR_TYPE
// (we pick PING_PROTO). The receiver's registered handler echoes a
// REPLY back to the sender's src_ip; the originator's handler then
// prints "Ping reply ...".
//
// Not real ICMP; the wire format is whatever we want as long as
// both ends agree.

#include "../graph.h"

// Protocol number lives in the IP header's `protocol` field. Picked
// far enough away from IP_HDR_TYPE (0x0800) and ARP_MSG (806) that
// dispatch can't be ambiguous. Not the real ICMP value (1) -- we
// just need something the receiver can recognise.
#define PING_PROTO   201

#define PING_REQ     1
#define PING_REPLY   2

#pragma pack(push, 1)
typedef struct PingMsg {
    short        type;          // PING_REQ / PING_REPLY
    short        seq;
    unsigned int origin_ip;     // host-byte-order; reply preserves it
} PingMsg;
#pragma pack(pop)

// Register the ping receive handler with L3's protocol-handler
// table. Call once at startup (after the graph + tables are
// built). Idempotent.
void ping_register(void);

// Originate a single REQUEST from `node` to `dst_ip_str`. The
// reply (if reachable) lands on the same node's L4 handler and
// prints "Ping reply seq=...".
void ping_send_request(Node* node, char* dst_ip_str, short seq);

#endif
