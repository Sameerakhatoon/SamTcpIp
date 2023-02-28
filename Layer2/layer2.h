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
#define IP_HDR_TYPE     0x0800     // ether-type for IPv4
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

// ch7: 802.1Q VLAN tag - 4 bytes spliced between src_mac and type
// in a tagged frame. Bit-fields packed into the 16-bit tci word.
#define VLAN_8021Q_PROTO 0x8100

typedef struct Vlan8021qHdr {
    short tpid;             // == 0x8100 in a tagged frame
    short tci_pcp : 3;      // priority code point (unused here)
    short tci_dei : 1;      // drop-eligible indicator (unused)
    short tci_vid : 12;     // 12-bit VLAN ID 1..4094
} Vlan8021qHdr;

typedef struct VlanEthernetHdr {
    MacAddr      dst_mac;
    MacAddr      src_mac;
    Vlan8021qHdr vlan_8021q_hdr;
    short        type;
    char         payload[248];
    unsigned int FCS;
} VlanEthernetHdr;

#pragma pack(pop)

// Sizes excluding payload. FCS sits AFTER payload bytes, so we
// subtract only the payload[].
#define ETH_HDR_SIZE_EXCL_PAYLOAD       (sizeof(EthernetHdr)     - 248)
#define VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD  (sizeof(VlanEthernetHdr) - 248)

// FCS lives at `payload + payload_size`.
#define ETH_FCS(eth_ptr, payload_size) \
    (*(unsigned int*)((char*)((eth_ptr)->payload) + (payload_size)))
#define VLAN_ETH_FCS(veth_ptr, payload_size) \
    (*(unsigned int*)((char*)((veth_ptr)->payload) + (payload_size)))

// Bytes 13..14 of any frame: in an untagged frame those are the
// ether-type; in a tagged frame they are the tpid (0x8100). Test
// that.
static inline Vlan8021qHdr* is_pkt_vlan_tagged(EthernetHdr* eth){
    Vlan8021qHdr* v =
        (Vlan8021qHdr*)((char*)eth + (sizeof(MacAddr) * 2));
    if(v->tpid == (short)VLAN_8021Q_PROTO){
        return v;
    }
    return 0;
}

static inline unsigned int GET_802_1Q_VLAN_ID(Vlan8021qHdr* v){
    return (unsigned int)v->tci_vid;
}

// Tagged + untagged share dst_mac/src_mac. The payload sits at
// different offsets; this helper picks the right one.
static inline char* GET_ETHERNET_HDR_PAYLOAD(EthernetHdr* eth){
    if(is_pkt_vlan_tagged(eth)){
        return ((VlanEthernetHdr*)eth)->payload;
    }
    return eth->payload;
}

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

// ch5/6/7 helpers used by the qualifier below.
extern unsigned int get_access_intf_operating_vlan_id(Interface* intf);
extern bool         is_trunk_interface_vlan_enabled(Interface* intf, unsigned int vlan_id);

// ch7: L2 acceptance gate, full VLAN-aware version. Returns true if
// the frame should be admitted to the receiving stack. If non-zero
// is written to *vlan_id_out, the caller must tag the frame with
// that VLAN before forwarding (case 6: untagged ingress on an
// ACCESS port that has a VLAN assigned).
//
// Decision table mirrors the PDF's "Frame Ingress" 10-case table.
static inline bool l2_frame_recv_qualify_on_interface(Interface* intf,
                                                      EthernetHdr* eth,
                                                      unsigned int* vlan_id_out){
    *vlan_id_out = 0;
    Vlan8021qHdr* tag = is_pkt_vlan_tagged(eth);

    // case 10: neither L2 nor L3 configured -> drop.
    if(!IS_INTF_L3_MODE(intf) && IF_L2_MODE(intf) == L2_MODE_UNKNOWN){
        return false;
    }

    if(IF_L2_MODE(intf) == ACCESS){
        unsigned int intf_vlan = get_access_intf_operating_vlan_id(intf);
        // case 3: ACCESS, no VLAN assigned, untagged frame -> accept.
        // case 4: ACCESS, no VLAN assigned, tagged frame -> drop.
        if(intf_vlan == 0){
            return tag == 0;
        }
        // case 6: ACCESS, has VLAN, untagged frame -> tag and accept.
        if(!tag){
            *vlan_id_out = intf_vlan;
            return true;
        }
        // case 5: ACCESS, has VLAN, tagged -> accept iff VLANs match.
        return GET_802_1Q_VLAN_ID(tag) == intf_vlan;
    }

    if(IF_L2_MODE(intf) == TRUNK){
        // cases 7, 8: TRUNK + untagged -> drop.
        if(!tag){
            return false;
        }
        // case 9: TRUNK + tagged -> accept iff VLAN is in our member list.
        return is_trunk_interface_vlan_enabled(intf, GET_802_1Q_VLAN_ID(tag));
    }

    // L3 mode follows.
    // case 2: L3 + tagged -> drop.
    if(tag){
        return false;
    }
    // case 1a: L3 + dst MAC matches us.
    if(memcmp(IF_MAC(intf), eth->dst_mac.mac, sizeof(MacAddr)) == 0){
        return true;
    }
    // case 1b: L3 + broadcast.
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

// ch7: in-place packet tag / untag. Both return the new total
// packet size (4 bytes bigger / smaller respectively). Pre-condition
// for tag_pkt: the buffer behind `eth` has at least sizeof(Vlan8021qHdr)
// bytes of room (our send/recv buffers are 2 KB so this is fine).
unsigned int tag_pkt_with_vlan_id(EthernetHdr* eth, unsigned int total_pkt_size, int vlan_id);
unsigned int untag_pkt_with_vlan_id(EthernetHdr* eth, unsigned int total_pkt_size);

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
