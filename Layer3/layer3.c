#include <stddef.h>
#include <stdio.h>
#include "graph.h"

// Forward declarations.
void layer3_pkt_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size);

// ch4: print-only stub. Real L3 (routing table, IP forwarding)
// lands in ch8 / ch9.
void layer3_pkt_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    printf("Layer 3 Packet Recvd : Rcv Node %s, Intf : %s, data recvd : %s, pkt size : %zu\n",
           node->node_name, iif->if_name, pkt, pkt_size);
}
