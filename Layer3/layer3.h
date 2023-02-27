#ifndef SAMTCPIP_LAYER3_H
#define SAMTCPIP_LAYER3_H

// IPv4 header + per-Node routing table. ch8 ships:
//   - the wire IP header struct,
//   - a `RtTable` (intrusive glthread of `L3Route`),
//   - CRUD for routes (add, lookup-exact, delete, dump, clear),
//   - longest-prefix-match lookup,
//   - hook from net.c so configuring an interface IP or loopback
//     auto-installs the matching directly-connected route.
//
// ch9 will wire `layer3_pkt_recv_from_layer2` into the full
// forwarding pipeline (resolve next-hop -> ARP -> L2 send).

#include <stdbool.h>
#include <string.h>
#include "../graph.h"
#include "../gluethread/glthread.h"

// ---- IPv4 header ---------------------------------------------------------

#pragma pack(push, 1)

typedef struct IpHdr {
    unsigned int version    : 4;    // 4 for IPv4
    unsigned int ihl        : 4;    // 32-bit words; we use 5 (= 20 bytes)
    char         not_used;
    short        total_length;      // hdr + payload

    // Fragmentation members we never set / consult.
    short        identification;
    unsigned int unused_flag : 1;
    unsigned int DF_flag     : 1;
    unsigned int MORE_flag   : 1;
    unsigned int frag_offset : 13;

    short        ttl;
    short        protocol;
    short        checksum;          // never computed; left zero
    unsigned int src_ip;            // wire byte-order convention (see ch5/8)
    unsigned int dst_ip;
} IpHdr;

#pragma pack(pop)

static inline void initialize_ip_hdr(IpHdr* h){
    h->version        = 4;
    h->ihl            = 5;
    h->not_used       = 0;
    h->total_length   = 0;
    h->identification = 0;
    h->unused_flag    = 0;
    h->DF_flag        = 1;
    h->MORE_flag      = 0;
    h->frag_offset    = 0;
    h->ttl            = 64;
    h->protocol       = 0;
    h->checksum       = 0;
    h->src_ip         = 0;
    h->dst_ip         = 0;
}

// ---- Routing table -------------------------------------------------------

typedef struct L3Route L3Route;
struct L3Route {
    char     dest[16];               // dotted-quad prefix (post-mask)
    char     mask;                   // 0..32
    bool     is_direct;              // true: gw_ip + oif have no meaning
    char     gw_ip[16];              // next-hop IP for non-direct routes
    char     oif[IF_NAME_SIZE];      // outgoing interface name
    GlThread rt_glue;
};
GLTHREAD_TO_STRUCT(rt_glue_to_l3_route, L3Route, rt_glue);

struct RtTable {
    GlThread route_list;
};

void     init_rt_table(RtTable** rt_table);
L3Route* rt_table_lookup(RtTable* rt_table, char* ip_addr, char mask);
void     clear_rt_table(RtTable* rt_table);
void     delete_rt_table_entry(RtTable* rt_table, char* ip_addr, char mask);
void     rt_table_add_route(RtTable* rt_table, char* dst, char mask,
                            char* gw, char* oif);
void     rt_table_add_direct_route(RtTable* rt_table, char* dst, char mask);
void     dump_rt_table(RtTable* rt_table);

// Longest-prefix-match. `dest_ip` is in host byte order (our wire
// convention puts IPs in host byte order; see ch5).
L3Route* l3rib_lookup_lpm(RtTable* rt_table, unsigned int dest_ip);

#define IS_L3_ROUTES_EQUAL(a, b)                          \
    (strncmp((a)->dest, (b)->dest, 16) == 0 &&            \
     (a)->mask      == (b)->mask &&                       \
     (a)->is_direct == (b)->is_direct &&                  \
     strncmp((a)->gw_ip, (b)->gw_ip, 16) == 0 &&          \
     strncmp((a)->oif,   (b)->oif, IF_NAME_SIZE) == 0)

#endif
