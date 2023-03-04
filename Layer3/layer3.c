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

// ch12: pin the IPv4 header at exactly 20 bytes (RFC 791).
// If a future edit reintroduces a `short` where a `char` is
// required (or vice versa), the build fails loudly here.
_Static_assert(sizeof(IpHdr) == 20, "RFC 791 IPv4 header must be 20 bytes");

// ch12 test hook: when true, the next demote_packet_to_layer3
// call XORs one bit of the computed IP checksum before storing
// it. The receiver's verify path MUST drop the packet.
static bool g_force_ip_csum_corrupt = false;
void l3_test_force_ip_csum_corruption(bool on){
    g_force_ip_csum_corrupt = on;
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

// Send `pkt` (an IP datagram, pkt_size bytes) out via L2. If
// `outgoing_intf_name` is NULL the OIF is picked by subnet-match on
// `next_hop_ip` (case: direct route, host on connected subnet).
// `next_hop_ip` is in host byte order.
//
// ARP miss: fire a broadcast ARP request and drop this packet. Upper
// layers can retransmit. This matches the reference's pseudocode.
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
        send_arp_broadcast_request(node, oif, next_hop_str);
        return;
    }

    // Encap. Payload (IP datagram) must fit in our 248-byte payload[].
    if(pkt_size > sizeof(((EthernetHdr*)0)->payload)){
        printf("L3 send drop : %s : pkt too big (%zu)\n", node->node_name, pkt_size);
        return;
    }
    EthernetHdr* eth = calloc(1, sizeof(EthernetHdr));
    memcpy(eth->dst_mac.mac, arp->mac_addr.mac, sizeof(MacAddr));
    memcpy(eth->src_mac.mac, IF_MAC(oif),       sizeof(MacAddr));
    eth->type = IP_HDR_TYPE;
    memcpy(eth->payload, pkt, pkt_size);
    eth->FCS = 0;

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

    // ch12: verify the IP header checksum. RFC 1071 self-consistency:
    // running the algorithm over the whole header (including the
    // stored checksum field) yields 0 on a valid header. ihl*4 is
    // now 20 == sizeof(IpHdr); use ihl*4 to be option-tolerant if a
    // future chapter adds IP options.
    size_t hdr_size = ip_hdr->ihl * 4u;
    if(hdr_size < 20 || hdr_size > pkt_size){
        printf("L3 drop : %s : bad ihl=%u\n", node->node_name, ip_hdr->ihl);
        return;
    }
    if(inet_checksum(ip_hdr, hdr_size) != 0){
        printf("L3 drop : %s : IP checksum invalid\n", node->node_name);
        return;
    }

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
            char*  l4_hdr  = (char*)ip_hdr + hdr_size;
            size_t l4_size = ip_hdr->total_length - hdr_size;
            promote_pkt_to_layer4(node, iif, ip_hdr, l4_hdr, l4_size, ip_hdr->protocol);
            return;
        }
        // case 2: dst sits in a directly-connected subnet -> resolve
        // dst MAC and push to L2 (no specific oif; let push-down pick).
        layer3_pkt_push_down_to_layer2_for_l2routing(
                node, ip_hdr->dst_ip, NULL,
                (char*)ip_hdr, pkt_size);
        return;
    }

    // case 3: indirect route -> decrement TTL then forward to gw.
    ip_hdr->ttl--;
    if(ip_hdr->ttl == 0){
        printf("L3 drop : %s : TTL expired\n", node->node_name);
        return;
    }
    // ch12: TTL is part of the checksummed area, so we must
    // recompute. Simplest: zero and run inet_checksum again, store
    // back in NBO. RFC 1141's incremental-update trick is an
    // optimisation we skip.
    ip_hdr->checksum = 0;
    ip_hdr->checksum = htons(inet_checksum(ip_hdr, hdr_size));

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
    if(pkt_size > 200){
        printf("L3 originate drop : %s : payload too big\n", node->node_name);
        return;
    }
    // ch12: IpHdr is now exactly 20 bytes (RFC 791) so
    // sizeof(IpHdr) == ihl*4. The L3 payload starts immediately
    // after the header.
    char   buf[256] = {0};
    IpHdr* ip = (IpHdr*)buf;
    initialize_ip_hdr(ip);
    ip->protocol     = (unsigned char)protocol_number;
    size_t hdr_bytes = sizeof(IpHdr);
    ip->total_length = (unsigned short)(hdr_bytes + pkt_size);
    ip->dst_ip       = dest_ip_address;

    memcpy(buf + hdr_bytes, pkt, pkt_size);

    // Look up route + dispatch.
    L3Route* route = l3rib_lookup_lpm(NODE_RT_TABLE(node), ip->dst_ip);
    if(!route){
        printf("L3 originate drop : %s : no route\n", node->node_name);
        return;
    }

    // Pick src_ip = IP of the interface we'll send out of, so the
    // receiver's reply can route back via direct-route lookup.
    // Loopback is a poor source choice unless the receiver has a
    // route for it.
    Interface* src_intf = 0;
    if(l3_is_direct_route(route)){
        char dst_str[16];
        unsigned int net = htonl(ip->dst_ip);
        inet_ntop(AF_INET, &net, dst_str, 16);
        dst_str[15] = '\0';
        src_intf = node_get_matching_subnet_interface(node, dst_str);
    } else {
        src_intf = get_node_if_by_name(node, route->oif);
    }
    if(src_intf){
        unsigned int src_net = 0;
        inet_pton(AF_INET, IF_IP(src_intf), &src_net);
        ip->src_ip = htonl(src_net);
    } else if(node->node_nw_prop.is_lb_addr_config){
        // Last-resort fallback.
        unsigned int lb_net = 0;
        inet_pton(AF_INET, NODE_LO_ADDR(node), &lb_net);
        ip->src_ip = htonl(lb_net);
    }

    // ch12: compute the IP header checksum AFTER all header
    // fields are final. Stored in NBO so the wire bytes are
    // deterministic and the receiver's big-endian read yields 0.
    ip->checksum = 0;
    ip->checksum = htons(inet_checksum(ip, hdr_bytes));
    if(g_force_ip_csum_corrupt){
        // Test hook: flip a bit. Receiver MUST drop.
        ip->checksum ^= htons(0x0001);
    }

    if(l3_is_direct_route(route)){
        layer3_pkt_push_down_to_layer2_for_l2routing(
                node, ip->dst_ip, NULL, buf, ip->total_length);
        return;
    }
    unsigned int next_hop_ip = 0;
    inet_pton(AF_INET, route->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);
    layer3_pkt_push_down_to_layer2_for_l2routing(
            node, next_hop_ip, route->oif, buf, ip->total_length);
}
