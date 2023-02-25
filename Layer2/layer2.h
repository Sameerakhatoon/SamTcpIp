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

// L2 acceptance gate. ch6 rewrite for the L2-mode/L3-mode split:
//   - Not configured in either mode -> reject.
//   - L2 mode (ACCESS / TRUNK) -> accept everything; MAC-based
//     filtering happens (or doesn't) further up at the L2 switch.
//   - L3 mode -> accept only frames whose dst MAC matches our own,
//     or that carry the all-ones broadcast MAC.
static inline bool l2_frame_recv_qualify_on_interface(Interface* intf,
                                                      EthernetHdr* eth){
    // Neither L2 nor L3 configured -> drop.
    if(!IS_INTF_L3_MODE(intf) && IF_L2_MODE(intf) == L2_MODE_UNKNOWN){
        return false;
    }
    // Pure L2 (ACCESS or TRUNK) -> always accept.
    if(!IS_INTF_L3_MODE(intf)
       && (IF_L2_MODE(intf) == ACCESS || IF_L2_MODE(intf) == TRUNK)){
        return true;
    }
    // L3 + dst MAC matches us.
    if(IS_INTF_L3_MODE(intf)
       && memcmp(IF_MAC(intf), eth->dst_mac.mac, sizeof(MacAddr)) == 0){
        return true;
    }
    // L3 + broadcast.
    if(IS_INTF_L3_MODE(intf)
       && eth->dst_mac.mac[0] == (unsigned char)0xFF
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

// ch6: equality test extracted as a macro since ch6's arp_table
// fix needs it. (Old code memcmp'd whole structs which also
// compares the embedded glthread links - false negatives.)
#define IS_ARP_ENTRIES_EQUAL(a, b)                                          \
    (strncmp((char*)(a)->ip_addr.ip_addr, (char*)(b)->ip_addr.ip_addr, 16) == 0 && \
     strncmp((char*)(a)->mac_addr.mac,    (char*)(b)->mac_addr.mac,    6)  == 0 && \
     strncmp((a)->oif_name,               (b)->oif_name, IF_NAME_SIZE)     == 0)

// ----------------- ch6: MAC table + L2 switch -------------------------

typedef struct MacTableEntry MacTableEntry;
struct MacTableEntry {
    MacAddr  mac;                    // key
    char     oif_name[IF_NAME_SIZE];
    GlThread mac_entry_glue;
};
GLTHREAD_TO_STRUCT(mac_entry_glue_to_mac_entry, MacTableEntry, mac_entry_glue);

struct MacTable {
    GlThread mac_entries;
};

void           init_mac_table(MacTable** mac_table);
MacTableEntry* mac_table_lookup(MacTable* mac_table, char* mac);
void           clear_mac_table(MacTable* mac_table);
void           delete_mac_table_entry(MacTable* mac_table, char* mac);
bool           mac_table_entry_add(MacTable* mac_table, MacTableEntry* entry);
void           dump_mac_table(MacTable* mac_table);

// Entry point - called by layer2_frame_recv when the receiving
// interface is in L2 mode.
void l2_switch_recv_frame(Interface* iif, char* pkt, size_t pkt_size);

// ----------------- ch6: L2 mode config --------------------------------

// Set / unset an interface's L2 mode (and clear its IP if it was
// L3). Typo `vlan_membsership` preserved verbatim per book.
void interface_set_l2_mode(Node* node, Interface* intf, char* l2_mode_option);
void node_set_intf_l2_mode(Node* node, char* intf_name, IntfL2Mode mode);
void node_set_intf_vlan_membsership(Node* node, char* intf_name, unsigned int vlan_id);

#endif
