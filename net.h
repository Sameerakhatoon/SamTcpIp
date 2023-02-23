#ifndef SAMTCPIP_NET_H
#define SAMTCPIP_NET_H

// Per-Node and per-Interface networking properties. ch1 left the
// graph layer domain-blind; ch2 bolts MAC / IP / loopback / device
// type onto Node and Interface via two payload structs so the graph
// stays generic. ch5 grows NodeNwProp with an ARP table pointer
// (declared opaque here so layer2.h can stay out of graph.h).
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

// ch5: opaque pointer to the per-Node ARP table; full type in
// Layer2/layer2.h. Net layer never dereferences it.
typedef struct ArpTable  ArpTable;

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

typedef struct IpAddr      IpAddr;
typedef struct MacAddr     MacAddr;
typedef struct NodeNwProp  NodeNwProp;
typedef struct IntfNwProps IntfNwProps;

// ch5: packed so MAC / IP fields are byte-tight when these end up
// in real packet headers (ethernet_hdr_t / arp_hdr_t).
#pragma pack(push, 1)

struct IpAddr {
    unsigned char ip_addr[16];   // dotted-quad "aaa.bbb.ccc.ddd"
};

struct MacAddr {
    unsigned char mac[6];        // ch5: real 48-bit MAC
};

#pragma pack(pop)

struct NodeNwProp {
    unsigned int flags;              // L3_ROUTER | L2_SWITCH | HUB
    ArpTable*    arp_table;          // ch5: per-Node ARP cache
    bool         is_lb_addr_config;
    IpAddr       lb_addr;
};

struct IntfNwProps {
    // L2.
    MacAddr mac_add;                 // burned in by interface_assign_mac_address
    // L3. Interface is in L3 mode iff is_ipadd_config is true.
    bool    is_ipadd_config;
    IpAddr  ip_add;
    char    mask;
};

void init_node_nw_prop(NodeNwProp* p);
void init_intf_nw_prop(IntfNwProps* p);

// Lookup shortcuts. These touch full Node / Interface layouts, so
// callers must have graph.h included before using them.
#define IF_MAC(intf_ptr)        ((char*)((intf_ptr)->intf_nw_props.mac_add.mac))
#define IF_IP(intf_ptr)         ((char*)((intf_ptr)->intf_nw_props.ip_add.ip_addr))
#define NODE_LO_ADDR(node_ptr)  ((char*)((node_ptr)->node_nw_prop.lb_addr.ip_addr))
#define NODE_ARP_TABLE(node_ptr) ((node_ptr)->node_nw_prop.arp_table)

void interface_assign_mac_address(Interface* intf);

// Node-side setters.
bool node_set_device_type(Node* node, unsigned int flag);
bool node_set_loopback_address(Node* node, char* ip_addr);
bool node_set_intf_ip_address(Node* node, char* local_if, char* ip_addr, char mask);
bool node_unset_intf_ip_address(Node* node, char* local_if);

// ch5: walk the Node's interfaces and return the first whose
// configured subnet contains `ip_addr`. Used by ARP / routing.
Interface* node_get_matching_subnet_interface(Node* node, char* ip_addr);

// Network-aware dumps. dump_graph from ch1 still works; these add
// device + IP + MAC lines.
void dump_nw_graph(Graph* graph);
void dump_node_nw_props(Node* node);
void dump_intf_props(Interface* intf);

#endif
