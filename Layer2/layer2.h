#ifndef SAMTCPIP_LAYER2_H
#define SAMTCPIP_LAYER2_H

// Ethernet frame + ARP packet definitions, plus the per-Node ARP
// table. Layer 2 send / receive logic in layer2.c uses these to
// build broadcast requests, parse replies, and cache the
// IP -> (MAC, OIF) bindings.

#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include "../graph.h"
#include "../gluethread/glthread.h"
#include "../net.h"

// Ether-type / opcode constants (host-order values). On the wire
// every multi-byte field is NETWORK byte order: writers htons(),
// readers ntohs(). The course had ARP_MSG as decimal 806 written
// in host order, which a real peer reads as EtherType 0x2603.
#define ARP_BROAD_REQ   1
#define ARP_REPLY       2
#define ARP_MSG         0x0806     // ether-type for ARP
#define IP_HDR_TYPE     0x0800     // ether-type for IPv4
#define ARP_HW_ETHERNET 1
#define BROADCAST_MAC   0xFFFFFFFFFFFFULL

// Largest L3 payload one frame carries (Ethernet MTU).
#define ETH_MAX_PAYLOAD 1500

// All on-wire structs packed so members sit at byte-tight offsets.
#pragma pack(push, 1)

// RFC 826 ARP for IPv4 over Ethernet: 28 bytes, network byte order.
typedef struct ArpHdr {
    unsigned short hw_type;          // htons(1) for ethernet
    unsigned short proto_type;       // htons(0x0800) for IPv4
    unsigned char  hw_addr_len;      // 6 for MAC
    unsigned char  proto_addr_len;   // 4 for IPv4
    unsigned short op_code;          // htons(request or reply)
    MacAddr        src_mac;          // sender hardware addr
    unsigned int   src_ip;           // sender protocol addr (NBO)
    MacAddr        dst_mac;          // target hardware addr (zero in a request)
    unsigned int   dst_ip;           // target protocol addr (NBO)
} ArpHdr;

// 14-byte Ethernet II header + payload buffer. The FCS is not part
// of what we read or write: TAP neither delivers nor expects it,
// and real NICs compute it in hardware. Frames go out as
// ETH_HDR_SIZE_EXCL_PAYLOAD + payload bytes, never sizeof().
typedef struct EthernetHdr {
    MacAddr        dst_mac;
    MacAddr        src_mac;
    unsigned short type;             // NBO
    char           payload[ETH_MAX_PAYLOAD];
} EthernetHdr;

// ch7: 802.1Q VLAN tag - 4 bytes spliced between src_mac and type
// in a tagged frame. TCI = PCP(3) | DEI(1) | VID(12), one NBO word
// (bit-fields have compiler-defined order, so we mask instead).
#define VLAN_8021Q_PROTO 0x8100
#define VLAN_VID_MASK    0x0FFF

typedef struct Vlan8021qHdr {
    unsigned short tpid;             // htons(0x8100) in a tagged frame
    unsigned short tci;              // NBO: pcp<<13 | dei<<12 | vid
} Vlan8021qHdr;

typedef struct VlanEthernetHdr {
    MacAddr        dst_mac;
    MacAddr        src_mac;
    Vlan8021qHdr   vlan_8021q_hdr;
    unsigned short type;             // NBO
    char           payload[ETH_MAX_PAYLOAD];
} VlanEthernetHdr;

#pragma pack(pop)

_Static_assert(sizeof(ArpHdr) == 28, "RFC 826 ARP (IPv4/Ethernet) must be 28 bytes");

// Header sizes on the wire: 14 untagged, 18 tagged.
#define ETH_HDR_SIZE_EXCL_PAYLOAD       (sizeof(EthernetHdr)     - ETH_MAX_PAYLOAD)
#define VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD  (sizeof(VlanEthernetHdr) - ETH_MAX_PAYLOAD)

// Bytes 13..14 of any frame: in an untagged frame those are the
// ether-type; in a tagged frame they are the tpid (0x8100). Test
// that.
static inline Vlan8021qHdr* is_pkt_vlan_tagged(EthernetHdr* eth){
    Vlan8021qHdr* v =
        (Vlan8021qHdr*)((char*)eth + (sizeof(MacAddr) * 2));
    if(ntohs(v->tpid) == VLAN_8021Q_PROTO){
        return v;
    }
    return 0;
}

static inline unsigned int GET_802_1Q_VLAN_ID(Vlan8021qHdr* v){
    return (unsigned int)(ntohs(v->tci) & VLAN_VID_MASK);
}

static inline void SET_802_1Q_VLAN_ID(Vlan8021qHdr* v, unsigned int vlan_id){
    unsigned short tci = ntohs(v->tci);
    tci = (unsigned short)((tci & ~VLAN_VID_MASK) | (vlan_id & VLAN_VID_MASK));
    v->tci = htons(tci);
}

// EtherType of the frame in host order, looking past a VLAN tag.
static inline unsigned short GET_ETHERNET_TYPE(EthernetHdr* eth){
    if(is_pkt_vlan_tagged(eth)){
        return ntohs(((VlanEthernetHdr*)eth)->type);
    }
    return ntohs(eth->type);
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
    long     last_seen_ms;           // ch35: refreshed on install + lookup hit
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

// ch20: gratuitous ARP (RFC 5227 sec 2.3 announcement).
// Emits a broadcast ARP REPLY with src_ip == dst_ip == oif's IP.
// Peers see a "free" reply and update their ARP caches without
// having asked. Used:
//   - When the simulator-side IP changes (config interface ip).
//   - On manual `run node X arp-announce`.
// No-op if `oif` has no L3 IP configured.
void send_gratuitous_arp(Node* node, Interface* oif);

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
    long     last_seen_ms;           // ch35: refreshed on install + lookup hit
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

// ch35: aging. Walks the table, removes entries whose
// last_seen_ms is older than threshold. Returns count removed.
int            arp_age(ArpTable* arp_table, long threshold_ms);
int            mac_age(MacTable* mac_table, long threshold_ms);

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
