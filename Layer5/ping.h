#ifndef SAMTCPIP_PING_H
#define SAMTCPIP_PING_H

// Real ICMP ping application (ch11 rewrite).
//
// Sits above L3 on protocol number 1 (IANA ICMP). Emits ECHO
// REQUEST (type 8), expects ECHO REPLY (type 0). Wire format +
// checksum live in Layer3/icmp.{c,h}.
//
// ch10 shipped this as PING_PROTO=201 + a custom PingMsg. ch11
// replaces with the real thing.

#include "../graph.h"

// Register the ping receive handler with L3's protocol-handler
// table. Call once at startup. Idempotent.
void ping_register(void);

// Originate one ECHO REQUEST with the given sequence number.
// The reply lands on ping_recv and prints "Ping reply : ...".
void ping_send_request(Node* node, char* dst_ip_str, short seq);
// The same with this IP TTL (0: the default). With a TTL too
// small for the path a router answers with Time Exceeded.
void ping_send_request_ttl(Node* node, char* dst_ip_str, short seq, unsigned char ttl);

// ch11 test hook: same as ping_send_request but XORs one bit of
// the computed checksum before emit. Receiver MUST drop.
// tests/11-icmp.sh uses this via the `run node X ping-bad` CLI.
void ping_send_request_bad_checksum(Node* node, char* dst_ip_str, short seq);

#endif
