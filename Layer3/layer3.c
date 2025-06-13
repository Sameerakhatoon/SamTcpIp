#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../comm.h"
#include "../graph.h"
#include "../gluethread/glthread.h"
#include "../net.h"
#include "../utils.h"
#include "../Layer2/layer2.h"
#include "layer3.h"
#include "icmp.h"
#include "pmtu.h"

// ch12: pin the IPv4 header at exactly 20 bytes (RFC 791).
// If a future edit reintroduces a `short` where a `char` is
// required (or vice versa), the build fails loudly here.
_Static_assert(sizeof(IpHdr) == 20, "RFC 791 IPv4 header must be 20 bytes");

void ip_hdr_hton(IpHdr* h){
    h->total_length   = htons(h->total_length);
    h->identification = htons(h->identification);
    h->frag_off       = htons(h->frag_off);
    h->src_ip         = htonl(h->src_ip);
    h->dst_ip         = htonl(h->dst_ip);
}

void ip_hdr_ntoh(IpHdr* h){
    h->total_length   = ntohs(h->total_length);
    h->identification = ntohs(h->identification);
    h->frag_off       = ntohs(h->frag_off);
    h->src_ip         = ntohl(h->src_ip);
    h->dst_ip         = ntohl(h->dst_ip);
}

// The ICMP error token bucket (layer3.h, RFC 1812 4.3.2.8).
static unsigned int g_icmp_err_tokens = ICMP_ERR_BURST;
static uint64_t     g_icmp_err_refill_ms;

static bool icmp_err_allowed(Node* node){
    uint64_t now = net_now_ms();
    if(now - g_icmp_err_refill_ms >= ICMP_ERR_INTERVAL_MS){
        uint64_t n = (now - g_icmp_err_refill_ms) / ICMP_ERR_INTERVAL_MS;
        uint64_t t = g_icmp_err_tokens + n;
        g_icmp_err_tokens = t > ICMP_ERR_BURST ? ICMP_ERR_BURST : (unsigned int)t;
        g_icmp_err_refill_ms += n * ICMP_ERR_INTERVAL_MS;
    }
    if(!g_icmp_err_tokens){
        node->node_nw_prop.icmp_err_limited++;
        return false;
    }
    g_icmp_err_tokens--;
    return true;
}

// Not a unicast address an error can go to or be about (RFC 1812
// 4.3.2.7): 0.0.0.0, the limited broadcast, class D and E.
static bool ip_not_unicast(unsigned int ip){
    return ip == 0 || ip >= 0xE0000000u;
}

// RFC 792 Time Exceeded to the sender of `ip_hdr` (a received
// header, host order, `hdr_size` bytes, followed by its payload).
// RFC 1812 4.3.2.7: never about an ICMP error (only echo request and
// reply among ICMP messages here) nor about a fragment past the first.
// Any ICMP error of `type` and `code` (Time Exceeded, Destination
// Unreachable; `mtu` is Fragmentation Needed's next-hop MTU), never
// about a datagram from or to a broadcast or multicast address, and
// at most as often as the token bucket allows. True when it was sent.
static bool l3_send_icmp_error(Node* node, IpHdr* ip_hdr, size_t hdr_size,
                               unsigned char type, unsigned char code, unsigned short mtu){
    const unsigned char* l4 = (const unsigned char*)ip_hdr + hdr_size;
    size_t l4_size = ip_hdr->total_length - hdr_size;
    if(IP_HDR_FRAG_OFF(ip_hdr) != 0){
        return false;
    }
    if(ip_hdr->protocol == ICMP_PROTO
       && (l4_size < 1 || (l4[0] != ICMP_ECHO_REQUEST && l4[0] != ICMP_ECHO_REPLY))){
        return false;
    }
    if(ip_not_unicast(ip_hdr->src_ip) || ip_not_unicast(ip_hdr->dst_ip)){
        return false;
    }
    if(!icmp_err_allowed(node)){
        printf("L3 : %s : ICMP error type %u rate-limited\n", node->node_name, type);
        return false;
    }
    unsigned char msg[ICMP_ERROR_HDR_SIZE + 60 + 8];
    size_t quote = l4_size < 8 ? l4_size : 8;
    memset(msg, 0, ICMP_ERROR_HDR_SIZE);
    msg[0] = type;
    msg[1] = code;
    if(type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED){
        msg[6] = (unsigned char)(mtu >> 8);       // RFC 1191 next-hop MTU
        msg[7] = (unsigned char)mtu;
    }
    // The original header as it was on the wire: L3 turned the fixed
    // part to host order (the checksum and any options stay raw).
    IpHdr wire = *ip_hdr;
    ip_hdr_hton(&wire);
    memcpy(msg + ICMP_ERROR_HDR_SIZE, &wire, sizeof(IpHdr));
    memcpy(msg + ICMP_ERROR_HDR_SIZE + sizeof(IpHdr), (const char*)ip_hdr + sizeof(IpHdr),
           hdr_size - sizeof(IpHdr));
    memcpy(msg + ICMP_ERROR_HDR_SIZE + hdr_size, l4, quote);
    size_t len = ICMP_ERROR_HDR_SIZE + hdr_size + quote;
    unsigned short sum = htons(icmp_checksum(msg, len));
    memcpy(msg + 2, &sum, 2);
    demote_packet_to_layer3(node, (char*)msg, len, ICMP_PROTO, ip_hdr->src_ip);
    return true;
}

static void layer3_pkt_push_down_to_layer2_for_l2routing(
        Node* node, unsigned int next_hop_ip,
        char* outgoing_intf_name, char* pkt, size_t pkt_size);
static void ip_int_to_str(unsigned int ip_host_order, char* out16);

// A forwarded datagram larger than the outgoing MTU, without DF
// (host-order header, TTL already taken off): split into fragments of
// at most `mtu` bytes, each payload but the last a multiple of 8. The
// offsets continue the datagram's own (it may be a fragment already)
// and every piece but the last of a last fragment has MF. Each piece
// carries the whole header, options included (RFC 791 copies only the
// options with the copied flag: SamOS sends none, and passes on
// what it gets).
static void l3_forward_fragments(Node* node, IpHdr* ip_hdr, size_t hdr_size, size_t pkt_size,
                                 unsigned int next_hop, char* oif_name, unsigned int mtu){
    const char* data   = (const char*)ip_hdr + hdr_size;
    size_t data_len    = pkt_size - hdr_size;
    size_t chunk_max   = mtu > hdr_size ? ((mtu - hdr_size) / 8) * 8 : 0;
    unsigned int base  = IP_HDR_FRAG_OFF(ip_hdr) * 8u;
    bool last_mf       = IP_HDR_MF(ip_hdr);
    if(!chunk_max){
        printf("L3 drop : %s : MTU %u too small to forward\n", node->node_name, mtu);
        return;
    }
    node->node_nw_prop.fwd_fragmented++;
    size_t chunk;
    for(size_t off = 0; off < data_len; off += chunk){
        char buf[ETH_MAX_PAYLOAD];
        chunk = data_len - off < chunk_max ? data_len - off : chunk_max;
        bool more = off + chunk < data_len || last_mf;
        IpHdr* f = (IpHdr*)buf;
        memcpy(buf, ip_hdr, hdr_size);
        f->total_length = (unsigned short)(hdr_size + chunk);
        f->frag_off     = (unsigned short)((more ? IP_FLAG_MF : 0)
                                           | (((base + off) / 8) & IP_OFFSET_MASK));
        memcpy(buf + hdr_size, data + off, chunk);
        printf("IP frag fwd : %s : id=%u off=%zu len=%zu MF=%d\n",
               node->node_name, ip_hdr->identification, base + off, chunk, more);
        ip_hdr_hton(f);
        f->checksum = 0;
        f->checksum = htons(inet_checksum(f, hdr_size));
        layer3_pkt_push_down_to_layer2_for_l2routing(node, next_hop, oif_name, buf, hdr_size + chunk);
    }
}

// Forward a received datagram (host-order header, `pkt_size` bytes) to
// `next_hop` (host order) out of `oif_name` (NULL: the interface on
// next_hop's subnet). Dropped when forwarding is off or the TTL
// expired (then Time Exceeded goes back to the sender; the
// reference only dropped it). Larger than the outgoing MTU, it is
// fragmented, or with DF dropped with Fragmentation Needed (RFC 1191,
// the MTU in the message). Otherwise TTL-1, back to wire order, fresh
// checksum, out.
static void l3_forward(Node* node, IpHdr* ip_hdr, size_t hdr_size, size_t pkt_size,
                       unsigned int next_hop, char* oif_name){
    if(!node->node_nw_prop.ip_forward){
        node->node_nw_prop.fwd_refused++;
        printf("L3 drop : %s : not for us and forwarding is off\n", node->node_name);
        return;
    }
    if(ip_hdr->ttl <= 1){
        printf("L3 drop : %s : TTL expired\n", node->node_name);
        node->node_nw_prop.fwd_ttl_expired++;
        l3_send_icmp_error(node, ip_hdr, hdr_size, ICMP_TIME_EXCEEDED, 0, 0);
        return;
    }
    Interface* oif;
    if(oif_name){
        oif = get_node_if_by_name(node, oif_name);
    } else {
        char hop[16];
        ip_int_to_str(next_hop, hop);
        oif = node_get_matching_subnet_interface(node, hop);
    }
    unsigned int mtu = oif && IF_MTU(oif) ? IF_MTU(oif) : ETH_MAX_PAYLOAD;
    if(mtu > ETH_MAX_PAYLOAD){
        mtu = ETH_MAX_PAYLOAD;
    }
    if(pkt_size > mtu && IP_HDR_DF(ip_hdr)){
        printf("L3 drop : %s : %zu bytes with DF, MTU %u\n", node->node_name, pkt_size, mtu);
        node->node_nw_prop.fwd_frag_needed++;
        l3_send_icmp_error(node, ip_hdr, hdr_size, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
                           (unsigned short)mtu);
        return;
    }
    node->node_nw_prop.fwd_packets++;
    ip_hdr->ttl--;
    if(pkt_size > mtu){
        l3_forward_fragments(node, ip_hdr, hdr_size, pkt_size, next_hop, oif_name, mtu);
        return;
    }
    // TTL is inside the checksummed header, so recompute. RFC 1624's
    // incremental update is the known optimisation; a full pass over
    // 20 bytes is fine here.
    ip_hdr_hton(ip_hdr);
    ip_hdr->checksum = 0;
    ip_hdr->checksum = htons(inet_checksum(ip_hdr, hdr_size));
    layer3_pkt_push_down_to_layer2_for_l2routing(node, next_hop, oif_name, (char*)ip_hdr, pkt_size);
}

// ch12 test hook: when true, the next demote_packet_to_layer3
// call XORs one bit of the computed IP checksum before storing
// it. The receiver's verify path MUST drop the packet.
static bool g_force_ip_csum_corrupt = false;
void l3_test_force_ip_csum_corruption(bool on){
    g_force_ip_csum_corrupt = on;
}

// ch34: global IP id counter. Starts at 1 (0 = "unset" marker).
static unsigned short g_ip_id_next = 1;

// ch34: reassembly state. Tracks a single in-flight datagram
// by 4-tuple (src, dst, proto, id). Buffer indexed by byte
// offset (frag_offset * 8). `expected_bytes` becomes non-zero only
// once we've seen the LAST fragment (MF=0) and know the total.
// Up to IP_REASM_MAX_BYTES (layer3.h): the buffer grows as
// fragments arrive (`cap`), one bit per 8-byte slot says what is
// there, `filled` counts the slots; at most IP_REASM_MAX sets, each
// until its deadline. The ch34 version had a fixed 1600-byte buffer
// in each entry and counted 8 bytes for a tail of fewer.
#define IP_REASM_SLOTS  ((IP_REASM_MAX_BYTES + 7) / 8)
typedef struct ReassemblyEntry {
    unsigned int    src_ip;
    unsigned int    dst_ip;
    unsigned char   protocol;
    unsigned short  ip_id;
    unsigned char*  buf;
    unsigned int    cap;             // bytes allocated at buf
    unsigned char   slot_map[(IP_REASM_SLOTS + 7) / 8];
    unsigned int    filled;          // slots received
    unsigned int    end;             // the highest byte received + 1
    unsigned int    expected_bytes;  // set when MF=0 fragment arrives
    uint64_t        deadline_ms;
    Node*           node;
    Interface*      iif;             // first-seen ingress iface
    GlThread        glue;
} ReassemblyEntry;
GLTHREAD_TO_STRUCT(glue_to_reasm, ReassemblyEntry, glue);

static GlThread g_reasm_list;
static bool     g_reasm_inited = false;
static int      g_reasm_count;
static void ensure_reasm_init(void){
    if(!g_reasm_inited){
        init_glthread(&g_reasm_list);
        g_reasm_inited = true;
    }
}

static void reasm_free(ReassemblyEntry* r){
    remove_glthread(&r->glue);
    g_reasm_count--;
    free(r->buf);
    free(r);
}

int l3_reasm_count(void){
    return g_reasm_count;
}

// Drop the sets past their deadline. RFC 792 would have a Time
// Exceeded (code 1) go back when the first fragment had arrived; SamOS
// does not send it.
void l3_timer(void){
    ensure_reasm_init();
    uint64_t now = net_now_ms();
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_reasm_list, cur){
        ReassemblyEntry* r = glue_to_reasm(cur);
        if(now >= r->deadline_ms){
            printf("IP frag drop : %s : reassembly of id=%u timed out\n",
                   r->node->node_name, r->ip_id);
            r->node->node_nw_prop.reasm_timeouts++;
            reasm_free(r);
        }
    } ITERATE_GLTHREAD_END(&g_reasm_list, cur);
}

// Room in r->buf for `need` bytes: grow to the next 4 KiB (at least
// double), at most IP_REASM_MAX_BYTES. False without memory.
static bool reasm_room(ReassemblyEntry* r, unsigned int need){
    if(need <= r->cap){
        return true;
    }
    unsigned int cap = r->cap * 2;
    if(cap < need){
        cap = need;
    }
    cap = (cap + 4095) & ~4095u;
    if(cap > IP_REASM_MAX_BYTES){
        cap = IP_REASM_MAX_BYTES;
    }
    unsigned char* b = (unsigned char*)calloc(1, cap);
    if(!b){
        return false;
    }
    if(r->buf){
        memcpy(b, r->buf, r->cap);
        free(r->buf);
    }
    r->buf = b;
    r->cap = cap;
    return true;
}

static ReassemblyEntry* reasm_lookup(unsigned int src_ip, unsigned int dst_ip,
                                     unsigned char proto, unsigned short id){
    ensure_reasm_init();
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_reasm_list, cur){
        ReassemblyEntry* r = glue_to_reasm(cur);
        if(r->src_ip == src_ip && r->dst_ip == dst_ip
           && r->protocol == proto && r->ip_id == id){
            return r;
        }
    } ITERATE_GLTHREAD_END(&g_reasm_list, cur);
    return 0;
}

// Forward decl for the per-fragment emit helper.
static void emit_one_ip_fragment(Node* node, IpHdr* template_ip,
                                 const char* payload, size_t payload_size,
                                 unsigned short ip_id,
                                 bool more, unsigned short frag_offset_8,
                                 L3Route* route, bool df);

// ch30: shared source-IP selector. See layer3.h for the contract.
unsigned int node_pick_src_ip(Node* node, unsigned int dst_ip_host){
    // 1. LPM lookup: if the resolved route names an oif, use
    //    that interface's IP. (Indirect routes go through a
    //    gateway, so the egress oif is what matters for src.)
    L3Route* route = l3rib_lookup_lpm(NODE_RT_TABLE(node), dst_ip_host);
    if(route && !route->is_direct && route->oif[0] != '\0'){
        Interface* iface = get_node_if_by_name(node, route->oif);
        if(iface && IS_INTF_L3_MODE(iface)){
            unsigned int src_net = 0;
            if(inet_pton(AF_INET, IF_IP(iface), &src_net) == 1){
                return htonl(src_net);
            }
        }
    }
    // 2. Subnet-match for directly-connected.
    char dst_str[16];
    unsigned int net = htonl(dst_ip_host);
    inet_ntop(AF_INET, &net, dst_str, 16);
    dst_str[15] = '\0';
    Interface* iface = node_get_matching_subnet_interface(node, dst_str);
    if(iface){
        unsigned int src_net = 0;
        if(inet_pton(AF_INET, IF_IP(iface), &src_net) == 1){
            return htonl(src_net);
        }
    }
    // 3. Loopback fallback.
    if(node->node_nw_prop.is_lb_addr_config){
        unsigned int lb_net = 0;
        inet_pton(AF_INET, NODE_LO_ADDR(node), &lb_net);
        return htonl(lb_net);
    }
    return 0;
}

// Forward declarations.
static bool _rt_table_entry_add(RtTable* rt_table, L3Route* l3_route);
static bool l3_is_direct_route(L3Route* route);
static bool is_layer3_local_delivery(Node* node, unsigned int dst_ip);
static void promote_pkt_to_layer4(Node* node, Interface* iif, IpHdr* ip_hdr,
                                  char* l4_hdr, size_t pkt_size,
                                  int l4_protocol_number);
void        l3_register_l4_handler(int protocol_number, L4Handler handler);
static void layer3_pkt_push_down_to_layer2_for_l2routing(
        Node* node, unsigned int next_hop_ip,
        char* outgoing_intf_name, char* pkt, size_t pkt_size);
static void ip_int_to_str(unsigned int ip_host_order, char* out16);

void        init_rt_table(RtTable** rt_table);
L3Route*    rt_table_lookup(RtTable* rt_table, char* ip_addr, char mask);
void        clear_rt_table(RtTable* rt_table);
void        delete_rt_table_entry(RtTable* rt_table, char* ip_addr, char mask);
void        rt_table_add_route(RtTable* rt_table, char* dst, char mask,
                               char* gw, char* oif);
void        rt_table_add_direct_route(RtTable* rt_table, char* dst, char mask);
void        dump_rt_table(RtTable* rt_table);
L3Route*    l3rib_lookup_lpm(RtTable* rt_table, unsigned int dest_ip);
void        layer3_pkt_recv_from_layer2(Node* node, Interface* iif,
                                        char* pkt, size_t pkt_size,
                                        int   l3_protocol_number);
void        demote_packet_to_layer3(Node* node, char* pkt, size_t pkt_size,
                                    int protocol_number, unsigned int dest_ip_address);

// ---- routing table -------------------------------------------------------

void init_rt_table(RtTable** rt_table){
    *rt_table = calloc(1, sizeof(RtTable));
    init_glthread(&(*rt_table)->route_list);
}

L3Route* rt_table_lookup(RtTable* rt_table, char* ip_addr, char mask){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        if(strncmp(r->dest, ip_addr, 16) == 0 && r->mask == mask){
            return r;
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);
    return 0;
}

void clear_rt_table(RtTable* rt_table){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        remove_glthread(cur);
        free(r);
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);
}

void delete_rt_table_entry(RtTable* rt_table, char* ip_addr, char mask){
    char prefix[16];
    apply_mask(ip_addr, mask, prefix);
    L3Route* r = rt_table_lookup(rt_table, prefix, mask);
    if(!r){
        return;
    }
    remove_glthread(&r->rt_glue);
    free(r);
}

// LPM: walk the list; track the longest mask whose prefix matches
// `dest_ip` post-mask; fall back to 0.0.0.0/0 if present.
//
// ch9: `dest_ip` is in HOST byte order. The previous version called
// `inet_ntop` on the host-order value directly which printed the
// dotted-quad with bytes reversed (50.50.50.0 -> 0.50.50.50) so no
// match was ever found. Convert back to network order before
// stringifying.
L3Route* l3rib_lookup_lpm(RtTable* rt_table, unsigned int dest_ip){
    L3Route*     lpm           = 0;
    L3Route*     default_route = 0;
    char         longest_mask  = 0;
    char         dest_ip_str[16];
    char         subnet[16];
    GlThread*    cur           = 0;
    unsigned int net_order_ip  = htonl(dest_ip);

    inet_ntop(AF_INET, &net_order_ip, dest_ip_str, 16);
    dest_ip_str[15] = '\0';

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        memset(subnet, 0, sizeof(subnet));
        apply_mask(dest_ip_str, r->mask, subnet);

        if(strncmp("0.0.0.0", r->dest, 16) == 0 && r->mask == 0){
            default_route = r;
            continue;
        }
        // The whole prefix string. Upstream compared
        // strlen(subnet) bytes, so a route's dest that merely began
        // with the masked address matched: 10.1.0.1 took the route
        // for 10.1.0.10/32 (or 10.1.0.100/32).
        if(strncmp(subnet, r->dest, 16) == 0
           && r->mask >= longest_mask){
            longest_mask = r->mask;
            lpm          = r;
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);

    return lpm ? lpm : default_route;
}

void dump_rt_table(RtTable* rt_table){
    GlThread* cur = 0;
    printf("L3 Routing Table:\n");
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        printf("\t%-18s %-4d %-18s %s\n",
               r->dest, r->mask,
               r->is_direct ? "NA" : r->gw_ip,
               r->is_direct ? "NA" : r->oif);
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);
}

// Replace-or-insert. Returns false if an identical route already
// exists (caller should free the duplicate allocation).
static bool _rt_table_entry_add(RtTable* rt_table, L3Route* l3_route){
    L3Route* old = rt_table_lookup(rt_table, l3_route->dest, l3_route->mask);
    if(old && IS_L3_ROUTES_EQUAL(old, l3_route)){
        return false;
    }
    if(old){
        delete_rt_table_entry(rt_table, old->dest, old->mask);
    }
    init_glthread(&l3_route->rt_glue);
    glthread_add_next(&rt_table->route_list, &l3_route->rt_glue);
    return true;
}

void rt_table_add_direct_route(RtTable* rt_table, char* dst, char mask){
    rt_table_add_route(rt_table, dst, mask, 0, 0);
}

// Add a static route. `gw` + `oif` may be NULL/NULL for a direct
// route (then `is_direct` is set true and gw/oif slots stay empty).
//
// Idempotent: `_rt_table_entry_add` does an exact (dest+mask)
// lookup; if an identical row exists it returns false and we
// silently free the duplicate allocation.
void rt_table_add_route(RtTable* rt_table, char* dst, char mask,
                        char* gw, char* oif){
    char prefix[16];
    apply_mask(dst, mask, prefix);

    L3Route* r = calloc(1, sizeof(L3Route));
    strncpy(r->dest, prefix, 16);
    r->dest[15] = '\0';
    r->mask     = mask;
    if(!gw && !oif){
        r->is_direct = true;
    } else {
        r->is_direct = false;
        strncpy(r->gw_ip, gw, 16);
        r->gw_ip[15] = '\0';
        strncpy(r->oif, oif, IF_NAME_SIZE);
        r->oif[IF_NAME_SIZE - 1] = '\0';
    }
    if(!_rt_table_entry_add(rt_table, r)){
        free(r);
    }
}

// ---- ch9: forwarding pipeline -------------------------------------------

static bool l3_is_direct_route(L3Route* route){
    return route->is_direct;
}

// Convert host-order IPv4 integer to dotted-quad string.
static void ip_int_to_str(unsigned int ip_host_order, char* out16){
    unsigned int net = htonl(ip_host_order);
    inet_ntop(AF_INET, &net, out16, 16);
    out16[15] = '\0';
}

// Does `dst_ip` (host byte order) match the loopback or any
// configured interface IP on `node`?
static bool is_layer3_local_delivery(Node* node, unsigned int dst_ip){
    char dst_str[16];
    ip_int_to_str(dst_ip, dst_str);

    // Loopback.
    if(node->node_nw_prop.is_lb_addr_config
       && strncmp(NODE_LO_ADDR(node), dst_str, 16) == 0){
        return true;
    }
    // Each configured interface.
    for(unsigned int i = 0; i < MAX_INTF_PER_NODE; i++){
        Interface* intf = node->intf[i];
        if(!intf || !IS_INTF_L3_MODE(intf)){
            continue;
        }
        if(strncmp(IF_IP(intf), dst_str, 16) == 0){
            return true;
        }
    }
    return false;
}

// ch10: per-protocol L4 handler table. 256 slots indexed by the IP
// `protocol` field. Set by app code via l3_register_l4_handler.
static L4Handler l4_handlers[256] = {0};

void l3_register_l4_handler(int protocol_number, L4Handler handler){
    if(protocol_number < 0 || protocol_number >= 256){
        return;
    }
    l4_handlers[protocol_number] = handler;
}

static void promote_pkt_to_layer4(Node* node, Interface* iif, IpHdr* ip_hdr,
                                  char* l4_hdr, size_t pkt_size,
                                  int l4_protocol_number){
    if(l4_protocol_number >= 0 && l4_protocol_number < 256
       && l4_handlers[l4_protocol_number]){
        l4_handlers[l4_protocol_number](node, iif, ip_hdr, l4_hdr, pkt_size);
        return;
    }
    // No handler registered for this protocol - fall back to the
    // ch9 print so tests / debug still see something.
    printf("L4 Packet received : node %s : iif %s : proto %d : size %zu : payload `%s`\n",
           node->node_name,
           iif ? iif->if_name : "(self)",
           l4_protocol_number,
           pkt_size,
           l4_hdr);
}

// ch34: a fragment for us (host-order header, its payload at l4_hdr):
// into its reassembly set; the whole datagram goes to L4 once every
// byte up to the last fragment's end is there. Up to
// IP_REASM_MAX_BYTES with a growing buffer, a bounded number of sets
// (the oldest gives way), a deadline per set, and the malformed cases
// dropped: an empty fragment, a non-final one whose length is not a
// multiple of 8, data past the end the last fragment gave, two
// different ends.
static void l3_reassemble(Node* node, Interface* iif, IpHdr* ip_hdr, size_t hdr_size,
                          char* l4_hdr, size_t l4_size){
    unsigned int byte_off = IP_HDR_FRAG_OFF(ip_hdr) * 8u;
    bool mf = IP_HDR_MF(ip_hdr);
    if(!l4_size || (mf && (l4_size % 8) != 0) || byte_off + l4_size > IP_REASM_MAX_BYTES){
        printf("IP frag drop : %s : bad fragment id=%u off=%u len=%zu\n",
               node->node_name, ip_hdr->identification, byte_off, l4_size);
        node->node_nw_prop.reasm_dropped++;
        return;
    }
    ensure_reasm_init();
    l3_timer();
    ReassemblyEntry* r = reasm_lookup(ip_hdr->src_ip, ip_hdr->dst_ip,
                                      ip_hdr->protocol, ip_hdr->identification);
    if(!r){
        if(g_reasm_count >= IP_REASM_MAX){
            ReassemblyEntry* old = glue_to_reasm(g_reasm_list.right);   // the oldest
            printf("IP frag drop : %s : reassembly of id=%u pushed out\n",
                   node->node_name, old->ip_id);
            old->node->node_nw_prop.reasm_dropped++;
            reasm_free(old);
        }
        r = (ReassemblyEntry*)calloc(1, sizeof(ReassemblyEntry));
        if(!r){
            return;
        }
        r->src_ip      = ip_hdr->src_ip;
        r->dst_ip      = ip_hdr->dst_ip;
        r->protocol    = ip_hdr->protocol;
        r->ip_id       = ip_hdr->identification;
        r->node        = node;
        r->iif         = iif;
        r->deadline_ms = net_now_ms() + IP_REASM_TIMEOUT_MS;
        init_glthread(&r->glue);
        glthread_add_last(&g_reasm_list, &r->glue);
        g_reasm_count++;
    }
    unsigned int end = byte_off + (unsigned int)l4_size;
    bool bad = (r->expected_bytes && end > r->expected_bytes)
            || (!mf && r->expected_bytes && r->expected_bytes != end)
            || (!mf && r->end > end);
    if(bad || !reasm_room(r, end)){
        printf("IP frag drop : %s : reassembly of id=%u: %s\n", node->node_name, r->ip_id,
               bad ? "inconsistent fragments" : "no memory");
        node->node_nw_prop.reasm_dropped++;
        reasm_free(r);
        return;
    }
    memcpy(r->buf + byte_off, l4_hdr, l4_size);
    for(unsigned int s = byte_off / 8; s < (end + 7) / 8; s++){
        if(!(r->slot_map[s / 8] & (1u << (s % 8)))){
            r->slot_map[s / 8] |= (unsigned char)(1u << (s % 8));
            r->filled++;
        }
    }
    if(end > r->end){
        r->end = end;
    }
    if(!mf){
        r->expected_bytes = end;
    }
    printf("IP frag recv : %s : id=%u off=%u len=%zu MF=%u (have %u/%u slots)\n",
           node->node_name, ip_hdr->identification, byte_off, l4_size, mf ? 1u : 0u,
           r->filled, r->expected_bytes ? (r->expected_bytes + 7) / 8 : 0);
    if(!r->expected_bytes || r->filled != (r->expected_bytes + 7) / 8){
        return;
    }
    // Complete. Hand to L4 with this fragment's header made the whole
    // datagram's (src, dst and protocol are the set's).
    printf("IP frag done : %s : id=%u total=%u bytes\n",
           node->node_name, r->ip_id, r->expected_bytes);
    node->node_nw_prop.reasm_done++;
    remove_glthread(&r->glue);
    init_glthread(&r->glue);
    g_reasm_count--;
    ip_hdr->total_length = (unsigned short)(hdr_size + r->expected_bytes > 0xFFFF ? 0xFFFF
                                            : hdr_size + r->expected_bytes);
    ip_hdr->frag_off     = 0;
    promote_pkt_to_layer4(r->node, r->iif, ip_hdr, (char*)r->buf, r->expected_bytes, r->protocol);
    free(r->buf);
    free(r);
}

// Datagrams waiting for ARP. The reference dropped the
// packet that caused an ARP miss ("upper layers can retransmit"), so
// the first ping and the first SYN to a new neighbour were lost. Up to
// ARP_PENDING_MAX datagrams wait here, the oldest giving way, and go
// out when an ARP entry for their next hop is installed
// (l3_arp_resolved, from layer2's table update).
#define ARP_PENDING_MAX  16

typedef struct ArpPending {
    Node*        node;
    unsigned int next_hop_ip;      // host order
    Interface*   oif;
    size_t       size;
    char         pkt[ETH_MAX_PAYLOAD];
} ArpPending;

static ArpPending* g_arp_pending[ARP_PENDING_MAX];

static void arp_pending_add(Node* node, unsigned int next_hop_ip, Interface* oif,
                            char* pkt, size_t pkt_size){
    if(pkt_size > ETH_MAX_PAYLOAD){
        return;
    }
    int slot = 0;
    for(int i = 0; i < ARP_PENDING_MAX; i++){
        if(!g_arp_pending[i]){
            slot = i;
            break;
        }
    }
    if(g_arp_pending[slot]){
        free(g_arp_pending[slot]);     // full: the oldest (slot 0) goes
        memmove(g_arp_pending, g_arp_pending + 1, sizeof(g_arp_pending) - sizeof(g_arp_pending[0]));
        slot = ARP_PENDING_MAX - 1;
    }
    ArpPending* p = calloc(1, sizeof(ArpPending));
    if(!p){
        g_arp_pending[slot] = 0;
        return;
    }
    p->node        = node;
    p->next_hop_ip = next_hop_ip;
    p->oif         = oif;
    p->size        = pkt_size;
    memcpy(p->pkt, pkt, pkt_size);
    g_arp_pending[slot] = p;
}

void l3_arp_resolved(Node* node){
    for(int i = 0; i < ARP_PENDING_MAX; i++){
        ArpPending* p = g_arp_pending[i];
        if(!p || p->node != node){
            continue;
        }
        char hop[16];
        ip_int_to_str(p->next_hop_ip, hop);
        if(!arp_table_lookup(NODE_ARP_TABLE(node), hop)){
            continue;
        }
        g_arp_pending[i] = 0;
        layer3_pkt_push_down_to_layer2_for_l2routing(node, p->next_hop_ip, p->oif->if_name,
                                                     p->pkt, p->size);
        free(p);
    }
}

// Send `pkt` (an IP datagram, pkt_size bytes) out via L2. If
// `outgoing_intf_name` is NULL the OIF is picked by subnet-match on
// `next_hop_ip` (case: direct route, host on connected subnet).
// `next_hop_ip` is in host byte order.
//
// ARP miss: fire a broadcast ARP request and drop this packet. Upper
// layers can retransmit. This matches the reference's pseudocode.
// The packet waits for the reply instead (see above).
static void layer3_pkt_push_down_to_layer2_for_l2routing(
        Node* node, unsigned int next_hop_ip,
        char* outgoing_intf_name, char* pkt, size_t pkt_size){

    char       next_hop_str[16];
    Interface* oif = 0;

    ip_int_to_str(next_hop_ip, next_hop_str);

    if(outgoing_intf_name){
        oif = get_node_if_by_name(node, outgoing_intf_name);
        if(!oif){
            printf("L3 send drop : %s : oif %s not found\n",
                   node->node_name, outgoing_intf_name);
            return;
        }
    } else {
        oif = node_get_matching_subnet_interface(node, next_hop_str);
        if(!oif){
            printf("L3 send drop : %s : no matching subnet for %s\n",
                   node->node_name, next_hop_str);
            return;
        }
    }

    ArpEntry* arp = arp_table_lookup(NODE_ARP_TABLE(node), next_hop_str);
    if(!arp){
        printf("L3 send : %s : ARP miss for %s, firing broadcast on %s\n",
               node->node_name, next_hop_str, oif->if_name);
        arp_pending_add(node, next_hop_ip, oif, pkt, pkt_size);
        send_arp_broadcast_request(node, oif, next_hop_str);
        return;
    }

    // Encap. The IP datagram must fit one Ethernet payload (1500).
    if(pkt_size > ETH_MAX_PAYLOAD){
        printf("L3 send drop : %s : pkt too big (%zu)\n", node->node_name, pkt_size);
        return;
    }
    EthernetHdr* eth = calloc(1, sizeof(EthernetHdr));
    memcpy(eth->dst_mac.mac, arp->mac_addr.mac, sizeof(MacAddr));
    memcpy(eth->src_mac.mac, IF_MAC(oif),       sizeof(MacAddr));
    eth->type = htons(IP_HDR_TYPE);
    memcpy(eth->payload, pkt, pkt_size);

    // 14-byte header + datagram; no FCS (TAP / NIC owns it).
    send_pkt_out((char*)eth, ETH_HDR_SIZE_EXCL_PAYLOAD + pkt_size, oif);
    free(eth);
}

// L3 ingress. `pkt` points at the IP header (L2 already chopped).
void layer3_pkt_recv_from_layer2(Node* node, Interface* iif,
                                 char* pkt, size_t pkt_size,
                                 int   l3_protocol_number){
    if(l3_protocol_number != IP_HDR_TYPE){
        printf("L3 drop : %s : unknown protocol %d\n",
               node->node_name, l3_protocol_number);
        return;
    }

    IpHdr* ip_hdr = (IpHdr*)pkt;

    // ch12: validate the WIRE header before trusting any field.
    // RFC 1071 self-consistency: running the algorithm over the
    // whole header (including the stored checksum) yields 0 on a
    // valid header. ihl*4 keeps us option-tolerant.
    if(pkt_size < sizeof(IpHdr) || IP_HDR_VERSION(ip_hdr) != 4){
        printf("L3 drop : %s : not IPv4 (version=%u, %zu bytes)\n",
               node->node_name,
               pkt_size >= 1 ? IP_HDR_VERSION(ip_hdr) : 0u, pkt_size);
        return;
    }
    size_t hdr_size = IP_HDR_IHL(ip_hdr) * 4u;
    if(hdr_size < 20 || hdr_size > pkt_size){
        printf("L3 drop : %s : bad ihl=%u\n", node->node_name, IP_HDR_IHL(ip_hdr));
        return;
    }
    if(inet_checksum(ip_hdr, hdr_size) != 0){
        printf("L3 drop : %s : IP checksum invalid\n", node->node_name);
        return;
    }
    // Wire is network order; route + hand to L4 in host order.
    ip_hdr_ntoh(ip_hdr);
    if(ip_hdr->total_length < hdr_size || ip_hdr->total_length > pkt_size){
        printf("L3 drop : %s : bad total_length=%u (frame carries %zu)\n",
               node->node_name, ip_hdr->total_length, pkt_size);
        return;
    }
    // Trim any Ethernet padding past the datagram.
    pkt_size = ip_hdr->total_length;

    L3Route* route = l3rib_lookup_lpm(NODE_RT_TABLE(node), ip_hdr->dst_ip);
    if(!route){
        printf("L3 drop : %s : no route for dst\n", node->node_name);
        node->node_nw_prop.fwd_no_route++;
        // A router says so (RFC 1812 5.2.7.1: net unreachable);
        // a host (forwarding off) drops it quietly as before.
        if(node->node_nw_prop.ip_forward){
            if(l3_send_icmp_error(node, ip_hdr, hdr_size, ICMP_DEST_UNREACH, ICMP_UNREACH_NET, 0)){
                node->node_nw_prop.fwd_unreach_sent++;
            }
        }
        return;
    }

    if(l3_is_direct_route(route)){
        // case 1: addressed to self -> local delivery. ch12: chop at
        // ihl*4 (now equal to sizeof(IpHdr) = 20) per the real wire
        // format.
        if(is_layer3_local_delivery(node, ip_hdr->dst_ip)){
            // ch34: fragment? Accumulate into reassembly entry; on
            // completion, deliver the assembled L4 payload to the
            // registered protocol handler.
            bool is_fragment = IP_HDR_MF(ip_hdr) || (IP_HDR_FRAG_OFF(ip_hdr) != 0);
            char*  l4_hdr  = (char*)ip_hdr + hdr_size;
            size_t l4_size = ip_hdr->total_length - hdr_size;
            if(is_fragment){
                l3_reassemble(node, iif, ip_hdr, hdr_size, l4_hdr, l4_size);
                return;
            }
            promote_pkt_to_layer4(node, iif, ip_hdr, l4_hdr, l4_size, ip_hdr->protocol);
            return;
        }
        // case 2: dst sits in a directly-connected subnet -> this is
        // still a forward (a router hop), so TTL-1 like case 3, then
        // resolve dst MAC and push to L2 (let push-down pick the oif).
        l3_forward(node, ip_hdr, hdr_size, pkt_size, ip_hdr->dst_ip, NULL);
        return;
    }

    // case 3: indirect route -> TTL-1, back to wire order, forward to gw.
    unsigned int next_hop_ip = 0;
    inet_pton(AF_INET, route->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);
    l3_forward(node, ip_hdr, hdr_size, pkt_size, next_hop_ip, route->oif);
}

// Originate path. Caller hands us a raw L4 payload + dst; we build
// an IP header, then feed straight into the routing pipeline by
// invoking the same primitives recv-from-L2 uses. We must NOT route
// it back through `layer3_pkt_recv_from_layer2` because the local-
// delivery check there would loop a self-addressed packet back to
// L4 instead of sending it out the wire.
void demote_packet_to_layer3(Node* node, char* pkt, size_t pkt_size,
                             int protocol_number, unsigned int dest_ip_address){
    demote_packet_to_layer3_ttl(node, pkt, pkt_size, protocol_number, dest_ip_address, 0);
}

void demote_packet_to_layer3_ttl(Node* node, char* pkt, size_t pkt_size,
                                 int protocol_number, unsigned int dest_ip_address,
                                 unsigned char ttl){
    demote_packet_to_layer3_df(node, pkt, pkt_size, protocol_number, dest_ip_address, ttl, false);
}

void demote_packet_to_layer3_df(Node* node, char* pkt, size_t pkt_size,
                                int protocol_number, unsigned int dest_ip_address,
                                unsigned char ttl, bool df){
    // ch34: build a template IP header carrying just src_ip,
    // dst_ip, protocol, ttl. Per-fragment fields (id, total_length,
    // flags, frag_offset, checksum) get filled in by
    // emit_one_ip_fragment.
    IpHdr tmpl;
    initialize_ip_hdr(&tmpl);
    if(ttl){
        tmpl.ttl = ttl;
    }
    tmpl.protocol = (unsigned char)protocol_number;
    tmpl.dst_ip   = dest_ip_address;

    // Route lookup + src_ip pick happens ONCE; every fragment
    // takes the same path.
    L3Route* route = l3rib_lookup_lpm(NODE_RT_TABLE(node), tmpl.dst_ip);
    if(!route){
        printf("L3 originate drop : %s : no route\n", node->node_name);
        return;
    }
    Interface* src_intf = 0;
    if(l3_is_direct_route(route)){
        char dst_str[16];
        unsigned int net = htonl(tmpl.dst_ip);
        inet_ntop(AF_INET, &net, dst_str, 16);
        dst_str[15] = '\0';
        src_intf = node_get_matching_subnet_interface(node, dst_str);
    } else {
        src_intf = get_node_if_by_name(node, route->oif);
    }
    if(src_intf){
        unsigned int src_net = 0;
        inet_pton(AF_INET, IF_IP(src_intf), &src_net);
        tmpl.src_ip = htonl(src_net);
    } else if(node->node_nw_prop.is_lb_addr_config){
        unsigned int lb_net = 0;
        inet_pton(AF_INET, NODE_LO_ADDR(node), &lb_net);
        tmpl.src_ip = htonl(lb_net);
    }

    // ch34: split into fragments. RFC 791 requires per-fragment
    // payload to be a multiple of 8 bytes except the last. We
    // chunk into IP_MAX_FRAG_PAYLOAD - aligned chunks plus a
    // final possibly-short tail.
    unsigned short id = g_ip_id_next++;
    if(g_ip_id_next == 0) g_ip_id_next = 1;     // avoid 0 = "unset"

    // Per-fragment payload budget starts from the egress link MTU
    // (simulator links 120 -> 100 bytes, the TAP link 1500 -> 1480).
    size_t per_frag = IP_MAX_FRAG_PAYLOAD;
    if(src_intf && IF_MTU(src_intf) > sizeof(IpHdr)){
        per_frag = IF_MTU(src_intf) - sizeof(IpHdr);
    }
    if(per_frag > ETH_MAX_PAYLOAD - sizeof(IpHdr)){
        per_frag = ETH_MAX_PAYLOAD - sizeof(IpHdr);
    }
    // ch39: PMTUD - if a cached path MTU exists for this dst, it
    // CAPS the per-fragment IP payload. Cache stores total MTU
    // (header + payload); subtract sizeof(IpHdr) for the budget.
    unsigned int cached_mtu = pmtu_lookup(tmpl.dst_ip);
    if(cached_mtu > sizeof(IpHdr)){
        size_t pmtu_payload = cached_mtu - sizeof(IpHdr);
        if(pmtu_payload < per_frag) per_frag = pmtu_payload;
    }
    // round down to multiple of 8 (the LAST fragment can have any size).
    size_t per_frag_8 = (per_frag / 8) * 8;
    if(per_frag_8 == 0) per_frag_8 = per_frag;

    if(pkt_size <= per_frag){
        // Single-packet fast path: not fragmented. DF only when
        // asked for (every datagram SamOS sends has had DF clear: the
        // template's DF never reached the wire).
        emit_one_ip_fragment(node, &tmpl, pkt, pkt_size,
                             id, false, 0, route, df);
        return;
    }
    if(df){
        printf("L3 originate drop : %s : %zu bytes with DF, room for %zu\n",
               node->node_name, pkt_size, per_frag);
        return;
    }
    if(pkt_size > IP_REASM_MAX_BYTES){
        printf("L3 originate drop : %s : %zu bytes, more than an IP datagram holds\n",
               node->node_name, pkt_size);
        return;
    }

    size_t offset_bytes = 0;
    size_t remaining    = pkt_size;
    while(remaining > 0){
        size_t this_chunk = remaining > per_frag_8 ? per_frag_8 : remaining;
        bool   more       = (remaining > this_chunk);
        unsigned short frag_off_8 = (unsigned short)(offset_bytes / 8);
        printf("IP frag emit : %s : id=%u off=%zu len=%zu MF=%d\n",
               node->node_name, id, offset_bytes, this_chunk, more);
        emit_one_ip_fragment(node, &tmpl, pkt + offset_bytes, this_chunk,
                             id, more, frag_off_8, route, false);
        offset_bytes += this_chunk;
        remaining    -= this_chunk;
    }
}

// ch34: emit one fragment's worth of payload. The caller has
// already picked the route and src_ip in the template.
static void emit_one_ip_fragment(Node* node, IpHdr* template_ip,
                                 const char* payload, size_t payload_size,
                                 unsigned short ip_id,
                                 bool more, unsigned short frag_offset_8,
                                 L3Route* route, bool df){
    char   buf[ETH_MAX_PAYLOAD] = {0};
    IpHdr* ip = (IpHdr*)buf;
    size_t hdr_bytes  = sizeof(IpHdr);
    if(hdr_bytes + payload_size > sizeof(buf)){
        printf("L3 originate drop : %s : fragment too big (%zu)\n",
               node->node_name, payload_size);
        return;
    }
    // Build in host order...
    *ip = *template_ip;
    ip->total_length   = (unsigned short)(hdr_bytes + payload_size);
    ip->identification = ip_id;
    ip->frag_off       = (unsigned short)((more ? IP_FLAG_MF : 0) | (df ? IP_FLAG_DF : 0)
                                          | (frag_offset_8 & IP_OFFSET_MASK));

    memcpy(buf + hdr_bytes, payload, payload_size);

    // ...keep the host-order values push-down needs...
    unsigned int dst_host  = ip->dst_ip;
    size_t       wire_size = ip->total_length;

    // ...then flip to wire order and checksum the wire bytes.
    ip_hdr_hton(ip);
    ip->checksum = 0;
    ip->checksum = htons(inet_checksum(ip, hdr_bytes));
    if(g_force_ip_csum_corrupt){
        ip->checksum ^= htons(0x0001);
    }

    if(l3_is_direct_route(route)){
        layer3_pkt_push_down_to_layer2_for_l2routing(
                node, dst_host, NULL, buf, wire_size);
        return;
    }
    unsigned int next_hop_ip = 0;
    inet_pton(AF_INET, route->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);
    layer3_pkt_push_down_to_layer2_for_l2routing(
            node, next_hop_ip, route->oif, buf, wire_size);
}
