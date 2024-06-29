#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../comm.h"
#include "../graph.h"
#include "../net.h"
#include "../utils.h"
#include "layer2.h"

// Forward declarations.
static void promote_pkt_to_layer3(Node* node, Interface* iif, char* pkt, size_t pkt_size, int proto);
static void send_arp_reply_msg(EthernetHdr* eth_in, Interface* oif);
static void process_arp_broadcast_request(Node* node, Interface* iif, EthernetHdr* eth);
static void process_arp_reply_msg(Node* node, Interface* iif, EthernetHdr* eth);
void        layer2_frame_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size);
void        send_arp_broadcast_request(Node* node, Interface* oif, char* ip_addr);
void        send_gratuitous_arp(Node* node, Interface* oif);
void        init_arp_table(ArpTable** arp_table);
ArpEntry*   arp_table_lookup(ArpTable* arp_table, char* ip_addr);
void        clear_arp_table(ArpTable* arp_table);
void        delete_arp_table_entry(ArpTable* arp_table, char* ip_addr);
bool        arp_table_entry_add(ArpTable* arp_table, ArpEntry* arp_entry);
void        arp_table_update_from_arp_reply(ArpTable* arp_table, ArpHdr* arp_hdr, Interface* iif);
void        dump_arp_table(ArpTable* arp_table);
void        interface_set_l2_mode(Node* node, Interface* intf, char* l2_mode_option);
void        node_set_intf_l2_mode(Node* node, char* intf_name, IntfL2Mode mode);
void        node_set_intf_vlan_membsership(Node* node, char* intf_name, unsigned int vlan_id);

// ch6: hand-off when the recv interface is in ACCESS / TRUNK mode.
extern void l2_switch_recv_frame(Interface* iif, char* pkt, size_t pkt_size);

// ch9: real L3 receive entry point (declared in Layer3/layer3.h).
extern void layer3_pkt_recv_from_layer2(Node* node, Interface* iif,
                                        char* pkt, size_t pkt_size,
                                        int   l3_protocol_number);

static void promote_pkt_to_layer3(Node* node, Interface* iif, char* pkt,
                                  size_t pkt_size, int proto){
    layer3_pkt_recv_from_layer2(node, iif, pkt, pkt_size, proto);
}

// ---- ARP table -----------------------------------------------------------

void init_arp_table(ArpTable** arp_table){
    *arp_table = calloc(1, sizeof(ArpTable));
    init_glthread(&(*arp_table)->arp_entries);
}

// ch35: monotonic ms helper for aging.
#include <time.h>
static long l2_now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + (long)ts.tv_nsec / 1000000L;
}

ArpEntry* arp_table_lookup(ArpTable* arp_table, char* ip_addr){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, cur){
        ArpEntry* e = arp_glue_to_arp_entry(cur);
        if(strncmp((char*)e->ip_addr.ip_addr, ip_addr, 16) == 0){
            e->last_seen_ms = l2_now_ms();  // ch35: refresh on hit
            return e;
        }
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, cur);
    return 0;
}

void clear_arp_table(ArpTable* arp_table){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, cur){
        ArpEntry* e = arp_glue_to_arp_entry(cur);
        remove_glthread(cur);
        free(e);
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, cur);
}

void delete_arp_table_entry(ArpTable* arp_table, char* ip_addr){
    ArpEntry* e = arp_table_lookup(arp_table, ip_addr);
    if(!e){
        return;
    }
    remove_glthread(&e->arp_glue);
    free(e);
}

// Returns true if the entry was added or replaced (caller keeps the
// allocation). Returns false if an identical entry already exists
// (caller should free the duplicate).
bool arp_table_entry_add(ArpTable* arp_table, ArpEntry* arp_entry){
    ArpEntry* old = arp_table_lookup(arp_table, (char*)arp_entry->ip_addr.ip_addr);
    // ch6: compare via IS_ARP_ENTRIES_EQUAL macro rather than
    // memcmp'ing whole structs - the latter would include the
    // embedded glthread links and produce false negatives.
    if(old && IS_ARP_ENTRIES_EQUAL(old, arp_entry)){
        return false;
    }
    if(old){
        // Delete by the OLD entry's key (same as new but explicit).
        delete_arp_table_entry(arp_table, (char*)old->ip_addr.ip_addr);
    }
    init_glthread(&arp_entry->arp_glue);
    arp_entry->last_seen_ms = l2_now_ms();   // ch35: stamp on install
    glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
    return true;
}

// ch35: walk + remove stale ARP entries.
int arp_age(ArpTable* arp_table, long threshold_ms){
    if(!arp_table || threshold_ms < 0) return 0;
    long now = l2_now_ms();
    int removed = 0;
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, cur){
        ArpEntry* e = arp_glue_to_arp_entry(cur);
        long age = now - e->last_seen_ms;
        if(age < threshold_ms) continue;
        printf("ARP age : %s : timeout age=%ldms (threshold=%ldms)\n",
               (char*)e->ip_addr.ip_addr, age, threshold_ms);
        remove_glthread(cur);
        free(e);
        removed++;
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, cur);
    return removed;
}

void arp_table_update_from_arp_reply(ArpTable* arp_table, ArpHdr* arp_hdr, Interface* iif){
    assert(ntohs(arp_hdr->op_code) == ARP_REPLY);
    ArpEntry* e = calloc(1, sizeof(ArpEntry));
    // src_ip is already network order on the wire.
    inet_ntop(AF_INET, &arp_hdr->src_ip, (char*)e->ip_addr.ip_addr, 16);
    e->ip_addr.ip_addr[15] = '\0';
    memcpy(e->mac_addr.mac, arp_hdr->src_mac.mac, sizeof(MacAddr));
    strncpy(e->oif_name, iif->if_name, IF_NAME_SIZE);
    e->oif_name[IF_NAME_SIZE - 1] = '\0';
    if(!arp_table_entry_add(arp_table, e)){
        free(e);
    }
}

void dump_arp_table(ArpTable* arp_table){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, cur){
        ArpEntry* e = arp_glue_to_arp_entry(cur);
        printf("IP : %s, MAC : %u:%u:%u:%u:%u:%u, OIF = %s\n",
               e->ip_addr.ip_addr,
               e->mac_addr.mac[0], e->mac_addr.mac[1],
               e->mac_addr.mac[2], e->mac_addr.mac[3],
               e->mac_addr.mac[4], e->mac_addr.mac[5],
               e->oif_name);
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, cur);
}

// ---- ARP send ------------------------------------------------------------

// Fill the fixed part of an RFC 826 ARP header (network byte order).
static void arp_fill_common(ArpHdr* arp, unsigned short op){
    arp->hw_type        = htons(ARP_HW_ETHERNET);
    arp->proto_type     = htons(IP_HDR_TYPE);
    arp->hw_addr_len    = sizeof(MacAddr);
    arp->proto_addr_len = 4;
    arp->op_code        = htons(op);
}

// On-wire size of an untagged ARP frame: 14 + 28 = 42 bytes.
#define ARP_FRAME_SIZE  (ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(ArpHdr))

// Build + send a broadcast ARP request for `ip_addr` out of `oif`.
// If `oif` is NULL, look one up by subnet match against the node.
//
// Wire format is real RFC 826: 16-bit fields htons'd, IPs straight
// from inet_pton (already network order). The course stored IPs in
// host order, which only worked between two copies of this stack.
void send_arp_broadcast_request(Node* node, Interface* oif, char* ip_addr){
    if(!oif){
        oif = node_get_matching_subnet_interface(node, ip_addr);
        if(!oif){
            printf("Error : %s : No eligible subnet for ARP resolution for Ip-address : %s\n",
                   node->node_name, ip_addr);
            return;
        }
    }
    EthernetHdr* eth = calloc(1, sizeof(EthernetHdr));
    if(!eth){
        return;
    }

    layer2_fill_with_broadcast_mac((char*)eth->dst_mac.mac);
    memcpy(eth->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    eth->type = htons(ARP_MSG);

    ArpHdr* arp = (ArpHdr*)eth->payload;
    arp_fill_common(arp, ARP_BROAD_REQ);
    memcpy(arp->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    inet_pton(AF_INET, IF_IP(oif), &arp->src_ip);
    memset(arp->dst_mac.mac, 0, sizeof(MacAddr));
    inet_pton(AF_INET, ip_addr, &arp->dst_ip);

    send_pkt_out((char*)eth, ARP_FRAME_SIZE, oif);
    free(eth);
}

// ch20: gratuitous ARP (RFC 5227 sec 2.3 announcement).
//
// An ARP REPLY whose src_ip equals dst_ip equals OUR IP and
// whose target MAC is broadcast. Peers see a "free" reply and
// learn (or refresh) our IP -> MAC mapping. The Linux kernel,
// in particular, will populate its ARP cache for our IP before
// any active resolution happens - useful when a host needs to
// reach us soon after we configure our IP.
//
// Reuses arp_table_update_from_arp_reply on the peer side - no
// new ingress dispatch needed.
void send_gratuitous_arp(Node* node, Interface* oif){
    if(!oif || !IS_INTF_L3_MODE(oif)){
        printf("GARP : %s : oif has no L3 IP, skipping\n",
               node ? node->node_name : "?");
        return;
    }
    EthernetHdr* eth = calloc(1, sizeof(EthernetHdr));
    if(!eth){
        return;
    }
    layer2_fill_with_broadcast_mac((char*)eth->dst_mac.mac);
    memcpy(eth->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    eth->type = htons(ARP_MSG);

    ArpHdr* arp = (ArpHdr*)eth->payload;
    arp_fill_common(arp, ARP_REPLY);
    memcpy(arp->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    inet_pton(AF_INET, IF_IP(oif), &arp->src_ip);
    // RFC 5227: target MAC is broadcast; target IP equals our IP.
    memset(arp->dst_mac.mac, 0xFF, sizeof(MacAddr));
    arp->dst_ip = arp->src_ip;

    printf("GARP : %s : announcing %s on %s\n",
           node->node_name, IF_IP(oif), oif->if_name);
    send_pkt_out((char*)eth, ARP_FRAME_SIZE, oif);
    free(eth);
}

static void send_arp_reply_msg(EthernetHdr* eth_in, Interface* oif){
    ArpHdr*      arp_in = (ArpHdr*)eth_in->payload;
    EthernetHdr* eth_r  = calloc(1, sizeof(EthernetHdr));
    if(!eth_r){
        return;
    }
    memcpy(eth_r->dst_mac.mac, arp_in->src_mac.mac, sizeof(MacAddr));
    memcpy(eth_r->src_mac.mac, IF_MAC(oif),         sizeof(MacAddr));
    eth_r->type = htons(ARP_MSG);

    ArpHdr* arp_r = (ArpHdr*)eth_r->payload;
    arp_fill_common(arp_r, ARP_REPLY);
    memcpy(arp_r->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    inet_pton(AF_INET, IF_IP(oif), &arp_r->src_ip);
    memcpy(arp_r->dst_mac.mac, arp_in->src_mac.mac, sizeof(MacAddr));
    arp_r->dst_ip = arp_in->src_ip;       // both network order

    send_pkt_out((char*)eth_r, ARP_FRAME_SIZE, oif);
    free(eth_r);
}

// ---- ARP receive ---------------------------------------------------------

static void process_arp_reply_msg(Node* node, Interface* iif, EthernetHdr* eth){
    printf("%s : ARP reply msg recvd on interface %s of node %s\n",
           __FUNCTION__, iif->if_name, iif->att_node->node_name);
    arp_table_update_from_arp_reply(NODE_ARP_TABLE(node),
                                    (ArpHdr*)eth->payload, iif);
}

static void process_arp_broadcast_request(Node* node, Interface* iif, EthernetHdr* eth){
    printf("%s : ARP Broadcast msg recvd on interface %s of node %s\n",
           __FUNCTION__, iif->if_name, iif->att_node->node_name);

    ArpHdr* arp        = (ArpHdr*)eth->payload;
    char    ip_str[16] = {0};
    inet_ntop(AF_INET, &arp->dst_ip, ip_str, 16);
    ip_str[15] = '\0';

    if(strncmp(IF_IP(iif), ip_str, 16) != 0){
        printf("%s : ARP Broadcast req msg dropped, Dst IP address did not match\n",
               node->node_name);
        return;
    }
    send_arp_reply_msg(eth, iif);
}

void layer2_frame_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    EthernetHdr* eth         = (EthernetHdr*)pkt;
    unsigned int vlan_to_tag = 0;
    if(!l2_frame_recv_qualify_on_interface(iif, eth, &vlan_to_tag)){
        printf("L2 Frame Rejected\n");
        return;
    }
    printf("L2 Frame Accepted\n");

    // ch6/7: split by receiving interface's mode. L3 -> the existing
    // ARP / promote-to-L3 switch (uses GET_ETHERNET_HDR_PAYLOAD now
    // so tagged + untagged frames both find the ARP correctly). L2
    // -> tag if the qualifier flagged a case-6 untagged ingress,
    // then hand off to the L2 switch.
    if(IS_INTF_L3_MODE(iif)){
        unsigned short eth_type = GET_ETHERNET_TYPE(eth);
        switch(eth_type){
            case ARP_MSG: {
                ArpHdr* arp = (ArpHdr*)GET_ETHERNET_HDR_PAYLOAD(eth);
                // Only IPv4-over-Ethernet ARP; anything else is not ours.
                if(ntohs(arp->hw_type) != ARP_HW_ETHERNET
                   || ntohs(arp->proto_type) != IP_HDR_TYPE
                   || arp->hw_addr_len != sizeof(MacAddr)
                   || arp->proto_addr_len != 4){
                    printf("%s : ARP drop, unsupported hw/proto type\n", node->node_name);
                    break;
                }
                switch(ntohs(arp->op_code)){
                    case ARP_BROAD_REQ:
                        process_arp_broadcast_request(node, iif, eth);
                        break;
                    case ARP_REPLY:
                        process_arp_reply_msg(node, iif, eth);
                        break;
                    default:
                        break;
                }
                break;
            }
            case IP_HDR_TYPE: {
                // ch9: chop the L2 header before handing up. Payload
                // size = total - L2 header (no FCS in our payload size
                // calculation: pkt_size already excludes the trailing
                // FCS field as set by the sender).
                char*  payload  = GET_ETHERNET_HDR_PAYLOAD(eth);
                size_t hdr_size = is_pkt_vlan_tagged(eth)
                                  ? VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD
                                  : ETH_HDR_SIZE_EXCL_PAYLOAD;
                size_t l3_size  = pkt_size - hdr_size;
                promote_pkt_to_layer3(node, iif, payload, l3_size, IP_HDR_TYPE);
                break;
            }
            default:
                // Unknown ether-type: kept the old behavior of
                // promoting to L3 so existing ch5 "L2 Frame" tests
                // still report something. Real stacks would drop.
                promote_pkt_to_layer3(node, iif, pkt, pkt_size, eth_type);
                break;
        }
        return;
    }
    if(IF_L2_MODE(iif) == ACCESS || IF_L2_MODE(iif) == TRUNK){
        size_t new_size = pkt_size;
        if(vlan_to_tag){
            new_size = tag_pkt_with_vlan_id(eth, pkt_size, vlan_to_tag);
            assert(new_size != pkt_size);
        }
        l2_switch_recv_frame(iif, pkt, new_size);
    }
    // Else: drop.
}

// ---- ch6: L2 interface mode setters --------------------------------------

void interface_set_l2_mode(Node* node, Interface* intf, char* l2_mode_option){
    (void)node;
    IntfL2Mode mode;
    if(strncmp(l2_mode_option, "access", strlen("access")) == 0){
        mode = ACCESS;
    } else if(strncmp(l2_mode_option, "trunk", strlen("trunk")) == 0){
        mode = TRUNK;
    } else {
        assert(0);
    }

    // Case 1: was L3 -> stash the IP-config flag and flip to L2.
    if(IS_INTF_L3_MODE(intf)){
        intf->intf_nw_props.is_ipadd_config_backup = true;
        intf->intf_nw_props.is_ipadd_config        = false;
        IF_L2_MODE(intf) = mode;
        return;
    }
    // Case 2: not configured in any mode yet -> just set.
    if(IF_L2_MODE(intf) == L2_MODE_UNKNOWN){
        IF_L2_MODE(intf) = mode;
        return;
    }
    // Case 3: same mode -> no-op.
    if(IF_L2_MODE(intf) == mode){
        return;
    }
    // Case 4: ACCESS -> TRUNK = overwrite.
    if(IF_L2_MODE(intf) == ACCESS && mode == TRUNK){
        IF_L2_MODE(intf) = mode;
        return;
    }
    // Case 5: TRUNK -> ACCESS = overwrite AND zero all VLAN slots.
    // User must re-enable VLAN after demoting.
    if(IF_L2_MODE(intf) == TRUNK && mode == ACCESS){
        IF_L2_MODE(intf) = mode;
        for(unsigned int i = 0; i < MAX_VLAN_MEMBERSHIP; i++){
            intf->intf_nw_props.vlans[i] = 0;
        }
    }
}

// Convenience wrappers for topology builders.
void node_set_intf_l2_mode(Node* node, char* intf_name, IntfL2Mode mode){
    Interface* intf = get_node_if_by_name(node, intf_name);
    assert(intf);
    interface_set_l2_mode(node, intf, (char*)intf_l2_mode_str(mode));
}

// Typo "vlan_membsership" preserved verbatim from the reference.
//
// ch7: real implementation.
//   ACCESS: store in vlans[0]; one VLAN per port. Calling again
//           overwrites.
//   TRUNK : append to the first free slot; no-op if already a
//           member or membership full.
void node_set_intf_vlan_membsership(Node* node, char* intf_name, unsigned int vlan_id){
    Interface* intf = get_node_if_by_name(node, intf_name);
    assert(intf);

    if(IS_INTF_L3_MODE(intf)){
        printf("Error : Interface %s : L3 mode enabled\n", intf->if_name);
        return;
    }
    if(IF_L2_MODE(intf) != ACCESS && IF_L2_MODE(intf) != TRUNK){
        printf("Error : Interface %s : L2 mode not Enabled\n", intf->if_name);
        return;
    }
    if(IF_L2_MODE(intf) == ACCESS){
        intf->intf_nw_props.vlans[0] = vlan_id;
        return;
    }
    // TRUNK.
    unsigned int* free_slot = 0;
    for(unsigned int i = 0; i < MAX_VLAN_MEMBERSHIP; i++){
        if(!free_slot && intf->intf_nw_props.vlans[i] == 0){
            free_slot = &intf->intf_nw_props.vlans[i];
        } else if(intf->intf_nw_props.vlans[i] == vlan_id){
            return;
        }
    }
    if(free_slot){
        *free_slot = vlan_id;
        return;
    }
    printf("Error : Interface %s : Max Vlan membership limit reached\n", intf->if_name);
}

// ----------------- ch7: VLAN packet rewrite -------------------------------

// In-place tag of an untagged ethernet frame. Returns the new
// total packet size (4 bytes larger). If the frame is already
// tagged, the existing VID is overwritten and size is unchanged.
//
// Wire layout: the 4-byte tag (TPID 0x8100, TCI) sits between
// src_mac and the EtherType, all network byte order. We carry no
// FCS (TAP / NIC hardware owns it), so only type + payload shift.
unsigned int tag_pkt_with_vlan_id(EthernetHdr* eth, unsigned int total_pkt_size, int vlan_id){
    Vlan8021qHdr* existing = is_pkt_vlan_tagged(eth);
    if(existing){
        SET_802_1Q_VLAN_ID(existing, (unsigned int)vlan_id);
        return total_pkt_size;
    }
    // Shift (type + payload) right by 4 bytes, then write the tag.
    // memmove: source and destination overlap.
    unsigned int tail = total_pkt_size - (sizeof(MacAddr) * 2);
    char*        tag_at = (char*)eth + (sizeof(MacAddr) * 2);
    memmove(tag_at + sizeof(Vlan8021qHdr), tag_at, tail);

    Vlan8021qHdr* tag = (Vlan8021qHdr*)tag_at;
    tag->tpid = htons(VLAN_8021Q_PROTO);
    tag->tci  = htons((unsigned short)(vlan_id & VLAN_VID_MASK));   // pcp 0, dei 0

    return total_pkt_size + sizeof(Vlan8021qHdr);
}

// In-place untag. Returns the new total packet size (4 bytes
// smaller). No-op + same size if the frame wasn't tagged.
unsigned int untag_pkt_with_vlan_id(EthernetHdr* eth, unsigned int total_pkt_size){
    Vlan8021qHdr* tag = is_pkt_vlan_tagged(eth);
    if(!tag){
        return total_pkt_size;
    }
    unsigned int tail = total_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD
                      + sizeof(((EthernetHdr*)0)->type);
    memmove((char*)tag, (char*)tag + sizeof(Vlan8021qHdr), tail);
    return total_pkt_size - sizeof(Vlan8021qHdr);
}
