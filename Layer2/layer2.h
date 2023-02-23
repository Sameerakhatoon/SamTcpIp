#ifndef SAMTCPIP_LAYER2_H
#define SAMTCPIP_LAYER2_H

// Ethernet frame + ARP packet definitions, plus the per-Node ARP
// table. Layer 2 send / receive logic in layer2.c uses these to
// build broadcast requests, parse replies, and cache the
// IP -> (MAC, OIF) bindings.

#include <stdbool.h>
#include <string.h>
#include "../graph.h"
#include "../gluethread/glthread.h"
#include "../net.h"

// Ether-type / opcode constants. ARP_MSG is the ether-type for ARP
// frames; the per-packet op_code distinguishes request from reply.
#define ARP_BROAD_REQ   1
#define ARP_REPLY       2
#define ARP_MSG         806
#define BROADCAST_MAC   0xFFFFFFFFFFFFULL

// All on-wire structs packed so members sit at byte-tight offsets.
#pragma pack(push, 1)

typedef struct ArpHdr {
    short        hw_type;            // 1 for ethernet
    short        proto_type;         // 0x0800 for IPv4
    char         hw_addr_len;        // 6 for MAC
    char         proto_addr_len;     // 4 for IPv4
    short        op_code;            // request or reply
    MacAddr      src_mac;            // sender hardware addr
    unsigned int src_ip;             // sender protocol addr
    MacAddr      dst_mac;            // target hardware addr (zero in a request)
    unsigned int dst_ip;             // target protocol addr
} ArpHdr;

typedef struct EthernetHdr {
    MacAddr      dst_mac;
    MacAddr      src_mac;
    short        type;
    char         payload[248];       // simplified: max we handle is the ARP
    unsigned int FCS;                // unused; kept for layout
} EthernetHdr;

#pragma pack(pop)

// ch5: per-Node ARP cache.
struct ArpTable {
    GlThread arp_entries;
};

typedef struct ArpEntry ArpEntry;
struct ArpEntry {
    IpAddr   ip_addr;                // key
    MacAddr  mac_addr;
    char     oif_name[IF_NAME_SIZE];
    GlThread arp_glue;
};
GLTHREAD_TO_STRUCT(arp_glue_to_arp_entry, ArpEntry, arp_glue);

// L2 acceptance gate. Returns true if the receiving interface
// should let this frame into the stack:
//   - L2 (no IP) interfaces accept everything (later: VLAN gating).
//   - L3 interfaces accept frames addressed to their MAC, or to
//     the all-ones broadcast MAC.
static inline bool l2_frame_recv_qualify_on_interface(Interface* intf,
                                                      EthernetHdr* eth){
    if(!intf->intf_nw_props.is_ipadd_config){
        return true;
    }
    if(memcmp(IF_MAC(intf), eth->dst_mac.mac, sizeof(MacAddr)) == 0){
        return true;
    }
    if(eth->dst_mac.mac[0] == (unsigned char)0xFF
       && eth->dst_mac.mac[1] == (unsigned char)0xFF
       && eth->dst_mac.mac[2] == (unsigned char)0xFF
       && eth->dst_mac.mac[3] == (unsigned char)0xFF
       && eth->dst_mac.mac[4] == (unsigned char)0xFF
       && eth->dst_mac.mac[5] == (unsigned char)0xFF){
        return true;
    }
    return false;
}

// ARP send-side entry point. Builds + dispatches a broadcast ARP
// request for `ip_addr` out of `oif`.
void send_arp_broadcast_request(Node* node, Interface* oif, char* ip_addr);

// ARP table lifecycle + CRUD.
void      init_arp_table(ArpTable** arp_table);
ArpEntry* arp_table_lookup(ArpTable* arp_table, char* ip_addr);
void      clear_arp_table(ArpTable* arp_table);
void      delete_arp_table_entry(ArpTable* arp_table, char* ip_addr);
bool      arp_table_entry_add(ArpTable* arp_table, ArpEntry* arp_entry);
void      arp_table_update_from_arp_reply(ArpTable* arp_table,
                                          ArpHdr* arp_hdr,
                                          Interface* iif);
void      dump_arp_table(ArpTable* arp_table);

#endif
