#ifndef SAMTCPIP_NET_H
#define SAMTCPIP_NET_H

// Per-Node and per-Interface networking properties. ch1 left the
// graph layer domain-blind; ch2 bolts MAC / IP / loopback / device
// type onto Node and Interface via two payload structs so the graph
// stays generic. ch5 grew NodeNwProp with an opaque ArpTable
// pointer. ch6 adds an opaque MacTable pointer plus L2-mode +
// VLAN slots on each Interface.
//
// Include order: net.h is included BY graph.h, so net.h defines the
// payload structs and only forward-declares Node / Interface (used
// in function signatures, not in payload layout).

#include <stdbool.h>
#include <string.h>

// Forward declarations - definitions live in graph.h.
typedef struct Node      Node;
typedef struct Interface Interface;
typedef struct Graph     Graph;

// ch5/ch6/ch8: opaque pointers to the per-Node tables. Full types
// live next to their owning module (Layer2/layer2.h for the L2
// tables, Layer3/layer3.h for the routing table). Net layer never
// dereferences them.
typedef struct ArpTable  ArpTable;
typedef struct MacTable  MacTable;
typedef struct RtTable   RtTable;

// Device-type bit flags. A Node can be a router, an L2 switch, a
// hub, or any combination (router-bridge etc).
#define L3_ROUTER  (1 << 0)
#define L2_SWITCH  (1 << 1)
#define HUB        (1 << 2)

// Tiny bit-flag helpers. Kept inline here because no other module
// needs them yet.
#define IS_BIT_SET(n, pos) (((n) & (1u << (pos))) != 0)
#define SET_BIT(n, pos)    ((n) = (n) | (1u << (pos)))
#define UNSET_BIT(n, pos)  ((n) = (n) & ~(1u << (pos)))
#define TOGGLE_BIT(n, pos) ((n) = (n) ^ (1u << (pos)))

// ch6: per-Interface L2 operating mode. ACCESS = belongs to one
// VLAN. TRUNK = belongs to many. L2_MODE_UNKNOWN = pure L3 (or
// not configured yet).
typedef enum IntfL2Mode {
    ACCESS,
    TRUNK,
    L2_MODE_UNKNOWN,
} IntfL2Mode;

static inline const char* intf_l2_mode_str(IntfL2Mode m){
    switch(m){
        case ACCESS: return "access";
        case TRUNK:  return "trunk";
        default:     return "L2_MODE_UNKNWON";   // typo preserved
    }
}

#define MAX_VLAN_MEMBERSHIP 10

typedef struct IpAddr      IpAddr;
typedef struct MacAddr     MacAddr;
typedef struct NodeNwProp  NodeNwProp;
typedef struct IntfNwProps IntfNwProps;

// Packed so MAC / IP fields sit byte-tight in real packet headers.
#pragma pack(push, 1)

struct IpAddr {
    unsigned char ip_addr[16];   // dotted-quad "aaa.bbb.ccc.ddd"
};

struct MacAddr {
    unsigned char mac[6];        // real 48-bit MAC
};

#pragma pack(pop)

struct NodeNwProp {
    unsigned int flags;              // L3_ROUTER | L2_SWITCH | HUB
    ArpTable*    arp_table;          // ch5: per-Node ARP cache
    MacTable*    mac_table;          // ch6: per-Node mac-learning table
    RtTable*     rt_table;           // ch8: per-Node L3 routing table
    bool         is_lb_addr_config;
    IpAddr       lb_addr;
    // A datagram for another host is routed on only when
    // ip_forward is set. init_node_nw_prop sets it (the simulator's
    // routers always forwarded); SamOS clears it unless the boot
    // asks for it (samos.ip_forward, net/net.c). The counters are
    // what `route` prints.
    bool          ip_forward;
    unsigned long fwd_packets;       // routed on, TTL decremented
    unsigned long fwd_ttl_expired;   // TTL 1 or 0: dropped, Time Exceeded sent
    unsigned long fwd_refused;       // not for us, forwarding off
    unsigned long fwd_no_route;      // no route for the destination
};

struct IntfNwProps {
    // L2.
    MacAddr      mac_add;            // burned in by interface_assign_mac_address
    IntfL2Mode   intf_l2_mode;       // ch6: ACCESS / TRUNK / UNKNOWN
    unsigned int vlans[MAX_VLAN_MEMBERSHIP]; // ch6: trunk-mode membership
    bool         is_ipadd_config_backup;     // ch6: remembered when L2 takes over
    // L3. Interface is in L3 mode iff is_ipadd_config is true.
    bool         is_ipadd_config;
    IpAddr       ip_add;
    char         mask;
    // Largest IP datagram (header + payload) this interface sends
    // unfragmented. Simulator links default to a deliberately
    // narrow 120 so fragmentation is visible in tests; tap_attach
    // raises the TAP-backed interface to the Ethernet 1500.
    unsigned int mtu;
};

#define SIM_INTF_DEFAULT_MTU   120
#define ETH_DEFAULT_MTU        1500

void init_node_nw_prop(NodeNwProp* p);
void init_intf_nw_prop(IntfNwProps* p);

// Lookup shortcuts. These touch full Node / Interface layouts, so
// callers must have graph.h included before using them.
#define IF_MAC(intf_ptr)         ((char*)((intf_ptr)->intf_nw_props.mac_add.mac))
#define IF_IP(intf_ptr)          ((char*)((intf_ptr)->intf_nw_props.ip_add.ip_addr))
#define IF_L2_MODE(intf_ptr)     ((intf_ptr)->intf_nw_props.intf_l2_mode)
#define IS_INTF_L3_MODE(intf_ptr) ((intf_ptr)->intf_nw_props.is_ipadd_config == true)
#define IF_MTU(intf_ptr)         ((intf_ptr)->intf_nw_props.mtu)
#define NODE_LO_ADDR(node_ptr)   ((char*)((node_ptr)->node_nw_prop.lb_addr.ip_addr))
#define NODE_ARP_TABLE(node_ptr) ((node_ptr)->node_nw_prop.arp_table)
#define NODE_MAC_TABLE(node_ptr) ((node_ptr)->node_nw_prop.mac_table)
#define NODE_RT_TABLE(node_ptr)  ((node_ptr)->node_nw_prop.rt_table)

void interface_assign_mac_address(Interface* intf);

// Node-side setters.
bool node_set_device_type(Node* node, unsigned int flag);
bool node_set_loopback_address(Node* node, char* ip_addr);
bool node_set_intf_ip_address(Node* node, char* local_if, char* ip_addr, char mask);
bool node_unset_intf_ip_address(Node* node, char* local_if);

// ch5: walk the Node's interfaces and return the first whose
// configured subnet contains `ip_addr`. Used by ARP / routing.
Interface* node_get_matching_subnet_interface(Node* node, char* ip_addr);

// ch7: VLAN membership helpers. ACCESS version asserts that the
// interface is in ACCESS mode and returns vlans[0] (0 if none).
// TRUNK version asserts TRUNK and returns true iff vlan_id appears
// in the membership list.
unsigned int get_access_intf_operating_vlan_id(Interface* intf);
bool         is_trunk_interface_vlan_enabled(Interface* intf, unsigned int vlan_id);

// Network-aware dumps.
void dump_nw_graph(Graph* graph);
void dump_node_nw_props(Node* node);
void dump_intf_props(Interface* intf);

#endif
