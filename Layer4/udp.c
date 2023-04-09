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
#include "udp.h"

// Forward declarations.
static void           udp_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                               char* l4_payload, size_t l4_payload_size);
static unsigned short udp_pseudo_checksum(unsigned int src_ip,
                                          unsigned int dst_ip,
                                          const void* udp_seg,
                                          size_t udp_seg_len);
static UdpBinding*    udp_lookup_binding(Node* node, unsigned short port);
static unsigned int   udp_pick_src_ip(Node* node, unsigned int dst_ip);

bool        udp_bind(Node* node, unsigned short port, UdpPortHandler handler);
void        udp_unbind(Node* node, unsigned short port);
void        udp_register(void);
void        udp_send_pkt(Node* node, unsigned int dst_ip,
                         unsigned short src_port, unsigned short dst_port,
                         const char* payload, size_t payload_size);
void        udp_test_force_csum_corruption(bool on);
void        udp_echo_handler(Node* node, Interface* iif, IpHdr* ip_hdr,
                             UdpHdr* udp_hdr, char* payload, size_t payload_size);
void        udp_printer_handler(Node* node, Interface* iif, IpHdr* ip_hdr,
                                UdpHdr* udp_hdr, char* payload, size_t payload_size);
void        udp_install_default_handlers(Graph* topo);

// ---- Binding table ------------------------------------------------------

static GlThread g_udp_bindings;
static bool     g_bindings_initialized = false;

static void ensure_bindings_init(void){
    if(!g_bindings_initialized){
        init_glthread(&g_udp_bindings);
        g_bindings_initialized = true;
    }
}

static UdpBinding* udp_lookup_binding(Node* node, unsigned short port){
    ensure_bindings_init();
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_udp_bindings, cur){
        UdpBinding* b = glue_to_udp_binding(cur);
        if(b->node == node && b->port == port){
            return b;
        }
    } ITERATE_GLTHREAD_END(&g_udp_bindings, cur);
    return 0;
}

bool udp_bind(Node* node, unsigned short port, UdpPortHandler handler){
    ensure_bindings_init();
    UdpBinding* existing = udp_lookup_binding(node, port);
    if(existing){
        existing->handler = handler;
        return true;
    }
    UdpBinding* b = calloc(1, sizeof(UdpBinding));
    if(!b){
        return false;
    }
    b->node    = node;
    b->port    = port;
    b->handler = handler;
    init_glthread(&b->glue);
    glthread_add_next(&g_udp_bindings, &b->glue);
    return true;
}

void udp_unbind(Node* node, unsigned short port){
    UdpBinding* b = udp_lookup_binding(node, port);
    if(!b){
        return;
    }
    remove_glthread(&b->glue);
    free(b);
}

// ---- src_ip pick --------------------------------------------------------

// ch30: was inline, now uses shared node_pick_src_ip in layer3.
static unsigned int udp_pick_src_ip(Node* node, unsigned int dst_ip){
    return node_pick_src_ip(node, dst_ip);
}

// ---- Checksum -----------------------------------------------------------

static bool g_force_udp_csum_corruption = false;
void udp_test_force_csum_corruption(bool on){
    g_force_udp_csum_corruption = on;
}

// RFC 768 pseudo-header layout. src_ip / dst_ip handed in as HBO
// (the simulator's wire convention since ch5; closes at TAP in ch18).
// `udp_seg_len` is the UdpHdr+payload byte count. Caller has
// already zeroed UdpHdr.checksum.
#pragma pack(push, 1)
typedef struct UdpPseudoHdr {
    unsigned int   src_ip;
    unsigned int   dst_ip;
    unsigned char  zero;
    unsigned char  protocol;
    unsigned short udp_length;       // NBO (matches UdpHdr.length)
} UdpPseudoHdr;
#pragma pack(pop)

static unsigned short udp_pseudo_checksum(unsigned int src_ip,
                                          unsigned int dst_ip,
                                          const void* udp_seg,
                                          size_t udp_seg_len){
    unsigned char scratch[sizeof(UdpPseudoHdr) + 1500] = {0};
    if(udp_seg_len > sizeof(scratch) - sizeof(UdpPseudoHdr)){
        return 0;
    }
    UdpPseudoHdr* ph = (UdpPseudoHdr*)scratch;
    ph->src_ip     = src_ip;
    ph->dst_ip     = dst_ip;
    ph->zero       = 0;
    ph->protocol   = IP_PROTO_UDP;
    ph->udp_length = htons((unsigned short)udp_seg_len);
    memcpy(scratch + sizeof(UdpPseudoHdr), udp_seg, udp_seg_len);

    return inet_checksum(scratch, sizeof(UdpPseudoHdr) + udp_seg_len);
}

// ---- Originate ----------------------------------------------------------

void udp_send_pkt(Node* node, unsigned int dst_ip,
                  unsigned short src_port, unsigned short dst_port,
                  const char* payload, size_t payload_size){
    // demote_packet_to_layer3 caps at 200; keep us under that.
    if(payload_size > 150){
        printf("UDP send drop : %s : payload too big (%zu)\n",
               node->node_name, payload_size);
        return;
    }
    unsigned char seg[256] = {0};
    UdpHdr*       hdr      = (UdpHdr*)seg;
    size_t        seg_size = sizeof(UdpHdr) + payload_size;

    hdr->src_port = htons(src_port);
    hdr->dst_port = htons(dst_port);
    hdr->length   = htons((unsigned short)seg_size);
    hdr->checksum = 0;
    memcpy(seg + sizeof(UdpHdr), payload, payload_size);

    unsigned int src_ip = udp_pick_src_ip(node, dst_ip);

    // Stored in NBO so the wire bytes are byte-stable and the
    // receiver's big-endian read yields 0 (same trap as ch11/ch12).
    hdr->checksum = htons(udp_pseudo_checksum(src_ip, dst_ip, seg, seg_size));
    if(g_force_udp_csum_corruption){
        hdr->checksum ^= htons(0x0001);
    }

    demote_packet_to_layer3(node, (char*)seg, seg_size,
                            IP_PROTO_UDP, dst_ip);
}

// ---- L3 dispatch + per-port demux --------------------------------------

static void udp_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                     char* l4_payload, size_t l4_payload_size){
    if(l4_payload_size < sizeof(UdpHdr)){
        printf("UDP recv : %s : runt segment (%zu bytes)\n",
               node->node_name, l4_payload_size);
        return;
    }
    UdpHdr* hdr = (UdpHdr*)l4_payload;

    // RFC 768: csum=0 on the wire means "checksum disabled"; we
    // don't verify in that case. ch13 always computes, so this
    // branch only matters if a future chapter (real Linux UDP)
    // delivers a csum=0 segment.
    if(hdr->checksum != 0){
        if(udp_pseudo_checksum(ip_hdr->src_ip, ip_hdr->dst_ip,
                               hdr, l4_payload_size) != 0){
            printf("UDP recv : %s : checksum invalid (drop)\n",
                   node->node_name);
            return;
        }
    }

    unsigned short dst_port = ntohs(hdr->dst_port);

    UdpBinding* b = udp_lookup_binding(node, dst_port);
    if(!b){
        // Per PLAN.md rule 1, no ICMP Port-Unreach emit yet. Just
        // log + drop. The chapter that ships ICMP errors will wire
        // this point.
        printf("UDP recv : %s : no binding for port %u (drop)\n",
               node->node_name, dst_port);
        return;
    }

    char*  app_payload = l4_payload + sizeof(UdpHdr);
    size_t app_size    = l4_payload_size - sizeof(UdpHdr);
    b->handler(node, iif, ip_hdr, hdr, app_payload, app_size);
}

void udp_register(void){
    l3_register_l4_handler(IP_PROTO_UDP, udp_recv);
}

// ---- Built-in handlers --------------------------------------------------

void udp_echo_handler(Node* node, Interface* iif, IpHdr* ip_hdr,
                      UdpHdr* udp_hdr, char* payload, size_t payload_size){
    (void)iif;
    unsigned short src_port = ntohs(udp_hdr->src_port);
    unsigned short dst_port = ntohs(udp_hdr->dst_port);

    char src_str[16];
    unsigned int net = htonl(ip_hdr->src_ip);
    inet_ntop(AF_INET, &net, src_str, 16);
    src_str[15] = '\0';

    printf("UDP echo : %s : recv %zu bytes on port %u from %s:%u, echoing\n",
           node->node_name, payload_size, dst_port, src_str, src_port);

    udp_send_pkt(node, ip_hdr->src_ip, dst_port, src_port,
                 payload, payload_size);
}

void udp_printer_handler(Node* node, Interface* iif, IpHdr* ip_hdr,
                         UdpHdr* udp_hdr, char* payload, size_t payload_size){
    (void)iif;
    unsigned short src_port = ntohs(udp_hdr->src_port);
    unsigned short dst_port = ntohs(udp_hdr->dst_port);

    char src_str[16];
    unsigned int net = htonl(ip_hdr->src_ip);
    inet_ntop(AF_INET, &net, src_str, 16);
    src_str[15] = '\0';

    char preview[33] = {0};
    size_t n = payload_size < 32 ? payload_size : 32;
    memcpy(preview, payload, n);

    printf("UDP printer : %s : port %u from %s:%u : `%s`\n",
           node->node_name, dst_port, src_str, src_port, preview);
}

void udp_install_default_handlers(Graph* topo){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&topo->node_list, cur){
        Node* n = graph_glue_to_node(cur);
        udp_bind(n, UDP_ECHO_PORT,    udp_echo_handler);
        udp_bind(n, UDP_PRINTER_PORT, udp_printer_handler);
    } ITERATE_GLTHREAD_END(&topo->node_list, cur);
}
