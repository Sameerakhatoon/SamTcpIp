#ifndef SAMTCPIP_COMM_H
#define SAMTCPIP_COMM_H

// Packet exchange simulator. Each Node binds a UDP socket on a
// unique local port (40000+). To send a packet from Node A to its
// peer Node B on a given link, A serializes the destination
// interface name as 16-byte aux header then sendto's B's port on
// 127.0.0.1. A single receiver thread selects() across every Node
// socket and dispatches each datagram into pkt_receive on the
// correct (node, interface) pair.
//
// Why aux info: the recv socket is on the *node*, not the
// interface. The destination interface name must travel with the
// payload so the receiver can identify which port a frame "came in
// on" for its L2 / L3 logic.

#include <stddef.h>
#include "graph.h"

#define MAX_PACKET_BUFFER_SIZE 2048

// Lifecycle.
void init_udp_socket(Node* node);
void network_start_pkt_receiver_thread(Graph* topo);

// Public APIs used by the rest of the stack.
int send_pkt_out(char* pkt, size_t pkt_size, Interface* oif);
// ch6: flood the packet out of every interface of `node` EXCEPT
// `exempted_intf` (typically the interface the frame arrived on,
// so we don't echo it back). Pass NULL to skip nothing.
int send_pkt_flood(Node* node, Interface* exempted_intf, char* pkt, size_t pkt_size);

// Entry point hooked by the receiver thread once it has resolved
// the recv interface. Layer 2 takes it from here.
int pkt_receive(Node* node, Interface* iif, char* pkt, size_t pkt_size);

// The lock pkt_receive holds, for other threads that
// enter the stack (the timer).
void net_stack_lock(void);
void net_stack_unlock(void);
// A thread that runs tcp_timer every 10 ms (SamOS's
// kernel tick). nwcli_install starts it.
void net_start_timer_thread(void);
// Tests: of the TCP segments `node` sends from now on,
// pass `skip`, then drop `count`.
void comm_drop_tcp(Node* node, int skip, int count);

#endif
