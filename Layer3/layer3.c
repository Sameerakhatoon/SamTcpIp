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

// Forwarding a received (host-order) header: TTL-1, back to wire
// order, fresh checksum. Returns false if TTL expired (drop).
static bool l3_prepare_forward(Node* node, IpHdr* ip_hdr, size_t hdr_size){
    if(ip_hdr->ttl <= 1){
        printf("L3 drop : %s : TTL expired\n", node->node_name);
        return false;
    }
    ip_hdr->ttl--;
    // TTL is inside the checksummed header, so recompute. RFC 1624's
    // incremental update is the known optimisation; a full pass over
    // 20 bytes is fine here.
    ip_hdr_hton(ip_hdr);
    ip_hdr->checksum = 0;
    ip_hdr->checksum = htons(inet_checksum(ip_hdr, hdr_size));
    return true;
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
// offset (frag_offset * 8). `have_bytes` is the number of unique
// bytes received so far; `expected_bytes` becomes non-zero only
// once we've seen the LAST fragment (MF=0) and know the total.
typedef struct ReassemblyEntry {
    unsigned int    src_ip;
    unsigned int    dst_ip;
    unsigned char   protocol;
    unsigned short  ip_id;
    unsigned char   buf[IP_REASM_BUF_BYTES];
    bool            slot_filled[IP_REASM_BUF_BYTES / 8];
    unsigned int    have_bytes;
    unsigned int    expected_bytes;  // set when MF=0 fragment arrives
    Node*           node;
    Interface*      iif;             // first-seen ingress iface
    GlThread        glue;
} ReassemblyEntry;
GLTHREAD_TO_STRUCT(glue_to_reasm, ReassemblyEntry, glue);

static GlThread g_reasm_list;
static bool     g_reasm_inited = false;
static void ensure_reasm_init(void){
    if(!g_reasm_inited){
        init_glthread(&g_reasm_list);
        g_reasm_inited = true;
    }
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
                                 L3Route* route);

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
        if(strncmp(subnet, r->dest, strlen(subnet)) == 0
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
                ensure_reasm_init();
                ReassemblyEntry* r = reasm_lookup(ip_hdr->src_ip, ip_hdr->dst_ip,
                                                  ip_hdr->protocol,
                                                  ip_hdr->identification);
                if(!r){
                    r = (ReassemblyEntry*)calloc(1, sizeof(ReassemblyEntry));
                    if(!r) return;
                    r->src_ip   = ip_hdr->src_ip;
                    r->dst_ip   = ip_hdr->dst_ip;
                    r->protocol = ip_hdr->protocol;
                    r->ip_id    = ip_hdr->identification;
                    r->node     = node;
                    r->iif      = iif;
                    init_glthread(&r->glue);
                    glthread_add_last(&g_reasm_list, &r->glue);
                }
                unsigned int byte_off = IP_HDR_FRAG_OFF(ip_hdr) * 8u;
                if(byte_off + l4_size > IP_REASM_BUF_BYTES){
                    printf("IP frag drop : %s : reasm overflow id=%u\n",
                           node->node_name, ip_hdr->identification);
                    return;
                }
                memcpy(r->buf + byte_off, l4_hdr, l4_size);
                // Mark contiguous 8-byte slots; cheap accounting,
                // overcount is OK because we also check expected.
                unsigned int slot = byte_off / 8;
                unsigned int slots_n = (unsigned int)(l4_size + 7) / 8;
                for(unsigned int i = 0; i < slots_n; i++){
                    if(slot + i >= IP_REASM_BUF_BYTES / 8) break;
                    if(!r->slot_filled[slot + i]){
                        r->slot_filled[slot + i] = true;
                        r->have_bytes += 8;
                    }
                }
                if(!IP_HDR_MF(ip_hdr)){
                    r->expected_bytes = byte_off + (unsigned int)l4_size;
                }
                printf("IP frag recv : %s : id=%u off=%u len=%zu MF=%u (have %u/%u)\n",
                       node->node_name, ip_hdr->identification,
                       byte_off, l4_size, IP_HDR_MF(ip_hdr) ? 1u : 0u,
                       r->have_bytes, r->expected_bytes);
                if(r->expected_bytes > 0 && r->have_bytes >= r->expected_bytes){
                    // Complete. Deliver.
                    printf("IP frag done : %s : id=%u total=%u bytes\n",
                           node->node_name, ip_hdr->identification, r->expected_bytes);
                    // Hand to L4 via a synthesized IpHdr (the original
                    // first-fragment header is fine since src_ip /
                    // dst_ip / proto are stable).
                    promote_pkt_to_layer4(r->node, r->iif, ip_hdr,
                                          (char*)r->buf, r->expected_bytes,
                                          r->protocol);
                    remove_glthread(&r->glue);
                    free(r);
                }
                return;
            }
            promote_pkt_to_layer4(node, iif, ip_hdr, l4_hdr, l4_size, ip_hdr->protocol);
            return;
        }
        // case 2: dst sits in a directly-connected subnet -> this is
        // still a forward (a router hop), so TTL-1 like case 3, then
        // resolve dst MAC and push to L2 (let push-down pick the oif).
        unsigned int dst_host = ip_hdr->dst_ip;
        if(!l3_prepare_forward(node, ip_hdr, hdr_size)){
            return;
        }
        layer3_pkt_push_down_to_layer2_for_l2routing(
                node, dst_host, NULL,
                (char*)ip_hdr, pkt_size);
        return;
    }

    // case 3: indirect route -> TTL-1, back to wire order, forward to gw.
    if(!l3_prepare_forward(node, ip_hdr, hdr_size)){
        return;
    }

    unsigned int next_hop_ip = 0;
    inet_pton(AF_INET, route->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);

    layer3_pkt_push_down_to_layer2_for_l2routing(
            node, next_hop_ip, route->oif,
            (char*)ip_hdr, pkt_size);
}

// Originate path. Caller hands us a raw L4 payload + dst; we build
// an IP header, then feed straight into the routing pipeline by
// invoking the same primitives recv-from-L2 uses. We must NOT route
// it back through `layer3_pkt_recv_from_layer2` because the local-
// delivery check there would loop a self-addressed packet back to
// L4 instead of sending it out the wire.
void demote_packet_to_layer3(Node* node, char* pkt, size_t pkt_size,
                             int protocol_number, unsigned int dest_ip_address){
    // ch34: build a template IP header carrying just src_ip,
    // dst_ip, protocol, ttl. Per-fragment fields (id, total_length,
    // flags, frag_offset, checksum) get filled in by
    // emit_one_ip_fragment.
    IpHdr tmpl;
    initialize_ip_hdr(&tmpl);
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
        // Single-packet fast path: not fragmented.
        emit_one_ip_fragment(node, &tmpl, pkt, pkt_size,
                             id, false, 0, route);
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
                             id, more, frag_off_8, route);
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
                                 L3Route* route){
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
    ip->frag_off       = (unsigned short)((more ? IP_FLAG_MF : 0)
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
