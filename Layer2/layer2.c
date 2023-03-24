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

ArpEntry* arp_table_lookup(ArpTable* arp_table, char* ip_addr){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, cur){
        ArpEntry* e = arp_glue_to_arp_entry(cur);
        if(strncmp((char*)e->ip_addr.ip_addr, ip_addr, 16) == 0){
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
    glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
    return true;
}

void arp_table_update_from_arp_reply(ArpTable* arp_table, ArpHdr* arp_hdr, Interface* iif){
    assert(arp_hdr->op_code == ARP_REPLY);
    ArpEntry*    e      = calloc(1, sizeof(ArpEntry));
    unsigned int src_ip = htonl(arp_hdr->src_ip);
    inet_ntop(AF_INET, &src_ip, e->ip_addr.ip_addr, 16);
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

// Build + send a broadcast ARP request for `ip_addr` out of `oif`.
// If `oif` is NULL, look one up by subnet match against the node.
//
// Byte-order quirk preserved from the reference: src_ip / dst_ip
// are written with `htonl` AFTER inet_pton, so the wire value ends
// up in *host* byte order. The receiver `htonl`s again to recover.
// Consistent on loopback - would need fixing for a real peer.
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
    eth->type = ARP_MSG;

    ArpHdr* arp = (ArpHdr*)eth->payload;
    arp->hw_type        = 1;
    arp->proto_type     = 0x0800;
    arp->hw_addr_len    = sizeof(MacAddr);
    arp->proto_addr_len = 4;
    arp->op_code        = ARP_BROAD_REQ;
    memcpy(arp->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    inet_pton(AF_INET, IF_IP(oif), &arp->src_ip);
    arp->src_ip = htonl(arp->src_ip);
    memset(arp->dst_mac.mac, 0, sizeof(MacAddr));
    inet_pton(AF_INET, ip_addr, &arp->dst_ip);
    arp->dst_ip = htonl(arp->dst_ip);

    eth->FCS = 0;
    send_pkt_out((char*)eth, sizeof(EthernetHdr) + sizeof(ArpHdr), oif);
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
    eth->type = ARP_MSG;

    ArpHdr* arp = (ArpHdr*)eth->payload;
    arp->hw_type        = 1;
    arp->proto_type     = 0x0800;
    arp->hw_addr_len    = sizeof(MacAddr);
    arp->proto_addr_len = 4;
    arp->op_code        = ARP_REPLY;
    memcpy(arp->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    inet_pton(AF_INET, IF_IP(oif), &arp->src_ip);
    arp->src_ip = htonl(arp->src_ip);
    // RFC 5227: target MAC is broadcast; target IP equals our IP.
    memset(arp->dst_mac.mac, 0xFF, sizeof(MacAddr));
    arp->dst_ip = arp->src_ip;

    eth->FCS = 0;
    printf("GARP : %s : announcing %s on %s\n",
           node->node_name, IF_IP(oif), oif->if_name);
    send_pkt_out((char*)eth, sizeof(EthernetHdr) + sizeof(ArpHdr), oif);
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
    eth_r->type = ARP_MSG;

    ArpHdr* arp_r = (ArpHdr*)eth_r->payload;
    arp_r->hw_type        = 1;
    arp_r->proto_type     = 0x0800;
    arp_r->hw_addr_len    = sizeof(MacAddr);
    arp_r->proto_addr_len = 4;
    arp_r->op_code        = ARP_REPLY;
    memcpy(arp_r->src_mac.mac, IF_MAC(oif), sizeof(MacAddr));
    inet_pton(AF_INET, IF_IP(oif), &arp_r->src_ip);
    arp_r->src_ip = htonl(arp_r->src_ip);
    memcpy(arp_r->dst_mac.mac, arp_in->src_mac.mac, sizeof(MacAddr));
    arp_r->dst_ip = arp_in->src_ip;       // already in our wire convention

    eth_r->FCS = 0;
    send_pkt_out((char*)eth_r, sizeof(EthernetHdr) + sizeof(ArpHdr), oif);
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

    ArpHdr*      arp     = (ArpHdr*)eth->payload;
    unsigned int dst_ip  = htonl(arp->dst_ip);
    char         ip_str[16] = {0};
    inet_ntop(AF_INET, &dst_ip, ip_str, 16);
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
        switch(eth->type){
            case ARP_MSG: {
                ArpHdr* arp = (ArpHdr*)GET_ETHERNET_HDR_PAYLOAD(eth);
                switch(arp->op_code){
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
                promote_pkt_to_layer3(node, iif, pkt, pkt_size, eth->type);
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
unsigned int tag_pkt_with_vlan_id(EthernetHdr* eth, unsigned int total_pkt_size, int vlan_id){
    Vlan8021qHdr* existing = is_pkt_vlan_tagged(eth);
    if(existing){
        unsigned int payload_size = total_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
        existing->tci_vid = (short)vlan_id;
        VLAN_ETH_FCS((VlanEthernetHdr*)eth, payload_size) = 0;
        return total_pkt_size;
    }
    // Snapshot the untagged frame, then splice the VLAN tag in.
    char* tmp = calloc(1, total_pkt_size);
    memcpy(tmp, (char*)eth, total_pkt_size);

    unsigned int     payload_size = total_pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;
    VlanEthernetHdr* veth         = (VlanEthernetHdr*)eth;
    EthernetHdr*     old          = (EthernetHdr*)tmp;

    veth->vlan_8021q_hdr.tpid    = VLAN_8021Q_PROTO;
    veth->vlan_8021q_hdr.tci_pcp = 0;
    veth->vlan_8021q_hdr.tci_dei = 0;
    veth->vlan_8021q_hdr.tci_vid = (short)vlan_id;

    // Shift the (type + payload + FCS) tail forward by 4 bytes.
    memcpy((char*)&veth->type, (char*)&old->type,
           sizeof(old->type) + payload_size + sizeof(old->FCS));
    VLAN_ETH_FCS(veth, payload_size) = 0;
    free(tmp);

    return total_pkt_size + sizeof(Vlan8021qHdr);
}

// In-place untag. Returns the new total packet size (4 bytes
// smaller). No-op + same size if the frame wasn't tagged.
unsigned int untag_pkt_with_vlan_id(EthernetHdr* eth, unsigned int total_pkt_size){
    Vlan8021qHdr* tag = is_pkt_vlan_tagged(eth);
    if(!tag){
        return total_pkt_size;
    }
    VlanEthernetHdr* old = calloc(1, total_pkt_size);
    memcpy((char*)old, (char*)eth, total_pkt_size);
    unsigned int payload_size = total_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
    memcpy((char*)&eth->type, (char*)&old->type,
           sizeof(eth->type) + payload_size + sizeof(eth->FCS));
    ETH_FCS(eth, payload_size) = 0;
    free(old);
    return total_pkt_size - sizeof(Vlan8021qHdr);
}
