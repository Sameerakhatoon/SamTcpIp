#include <stddef.h>
#include <stdio.h>
#include "graph.h"

// Forward declarations.
static void promote_pkt_to_layer3(Node* node, Interface* iif, char* pkt, size_t pkt_size);
void        layer2_frame_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size);

// Stub - real layer3 lands in ch9.
extern void layer3_pkt_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size);

static void promote_pkt_to_layer3(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    layer3_pkt_recv(node, iif, pkt, pkt_size);
}

// ch4: just a print + immediate promote to Layer 3. ch5 will start
// actually inspecting ethernet headers and routing ARP traffic.
void layer2_frame_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    printf("Layer 2 Frame Recvd : Rcv Node %s, Intf : %s, data recvd : %s, pkt size : %zu\n",
           node->node_name, iif->if_name, pkt, pkt_size);
    promote_pkt_to_layer3(node, iif, pkt, pkt_size);
}
