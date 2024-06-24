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

// ch12: real RFC 791 IPv4 header. The course shipped this as
// 22 bytes (ttl / protocol / checksum were `short`); ch12 fixes
// to exactly 20 bytes so `ihl * 4 == sizeof(IpHdr)` holds and
// the offsets match the wire format. A static_assert in
// layer3.c pins this.
//
// Byte-order convention: multi-byte fields are in HOST byte
// order on our simulated wire, preserved from the course. Real
// RFC 791 uses network byte order. The byte-order rule says we close
// this at the TAP boundary in Milestone 1 ch18.
typedef struct IpHdr {
    unsigned int   version    : 4;   // 4 for IPv4
    unsigned int   ihl        : 4;   // 32-bit words; 5 (= 20 bytes)
    unsigned char  tos;              // type of service; left zero
    unsigned short total_length;     // hdr + payload

    // Fragmentation members we never set / consult.
    unsigned short identification;
    unsigned int   unused_flag : 1;
    unsigned int   DF_flag     : 1;
    unsigned int   MORE_flag   : 1;
    unsigned int   frag_offset : 13;

    unsigned char  ttl;              // hop limit (decremented on forward)
    unsigned char  protocol;         // IANA: 1=ICMP
    unsigned short checksum;         // RFC 1071 over the 20-byte header
    unsigned int   src_ip;
    unsigned int   dst_ip;
} IpHdr;

#pragma pack(pop)

static inline void initialize_ip_hdr(IpHdr* h){
    h->version        = 4;
    h->ihl            = 5;
    h->tos            = 0;
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

// ch12 test hook: toggles intentional IP-checksum corruption on
// originate. Production code never calls this. tests/12-real-ip.sh
// uses it via the `run node X ping-bad-ip <ip>` CLI to validate
// that the receiver's verify path actually drops bad IP headers.
void l3_test_force_ip_csum_corruption(bool on);

// ch34: IPv4 fragmentation parameters. demote splits payloads
// larger than IP_MAX_FRAG_PAYLOAD (the per-fragment IP payload
// budget; not counting the 20-byte IP header) into fragments
// with the same id, MF=1 except the last, frag_offset in 8-byte
// units per RFC 791. Receiver reassembles by (src_ip, dst_ip,
// protocol, id).
//
// 100 is small enough to make fragmentation visible in tests
// (a 250-byte UDP becomes 3 fragments) and 100 = 12*8 + 4 - we
// round chunk sizes down to a multiple of 8 except the last,
// which can carry a sub-8-byte tail.
#define IP_MAX_FRAG_PAYLOAD     100
#define IP_REASM_BUF_BYTES      1600    // max reassembled L4 payload
#define IP_REASM_TIMEOUT_MS     30000   // RFC 791 lower bound is 15s; we use 30s

// ch30: shared source-IP selector. UDP (ch13) and TCP (ch22)
// each had inline near-identical copies; promote here so a
// third caller (or curl-out) gets consistent semantics.
//
// `dst_ip` is in host byte order. Algorithm:
//   1. LPM lookup. If a route exists with an explicit oif
//      (not direct), use that interface's IP.
//   2. Else subnet-match: find the interface whose subnet
//      contains dst_ip directly.
//   3. Else fall back to the node's loopback IP if configured.
//   4. Else 0.
//
// Returns host-byte-order IP.
unsigned int node_pick_src_ip(struct Node* node, unsigned int dst_ip_host);

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

// ---- ch10: per-protocol L4 handler registry -----------------------------
//
// Apps (ping etc) call `l3_register_l4_handler` to install a
// callback keyed by the IP protocol number. `promote_pkt_to_layer4`
// looks it up after stripping the IP header. The IpHdr is passed
// through so the handler can read src_ip/dst_ip for the response.

typedef void (*L4Handler)(Node* node, Interface* iif, struct IpHdr* ip_hdr,
                          char* l4_payload, size_t l4_payload_size);
void l3_register_l4_handler(int protocol_number, L4Handler handler);

// ---- ch9: forwarding pipeline -------------------------------------------

// L3 ingress from L2 (L2 hdr already chopped). `pkt` points at the
// IP header; `pkt_size` includes the IP header + L3 payload.
void layer3_pkt_recv_from_layer2(Node* node, Interface* iif,
                                 char* pkt, size_t pkt_size,
                                 int   l3_protocol_number);

// Originate path: build an IP packet (src = node's loopback) from a
// user payload and feed it into the same forwarding pipeline as if
// it had arrived from L2. `dest_ip_address` is in host byte order
// (the same convention LPM uses). Used by the `ping` CLI.
void demote_packet_to_layer3(Node* node, char* pkt, size_t pkt_size,
                             int protocol_number, unsigned int dest_ip_address);

#endif
