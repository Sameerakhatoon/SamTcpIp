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
int send_pkt_flood(Node* node, char* pkt, size_t pkt_size);

// Entry point hooked by the receiver thread once it has resolved
// the recv interface. Layer 2 takes it from here.
int pkt_receive(Node* node, Interface* iif, char* pkt, size_t pkt_size);

#endif
