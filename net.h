#ifndef SAMTCPIP_NET_H
#define SAMTCPIP_NET_H

// Per-Node and per-Interface networking properties. ch1 left the
// graph layer domain-blind; ch2 bolts MAC / IP / loopback / device
// type onto Node and Interface via two payload structs so the graph
// stays generic.
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

struct IpAddr {
    char ip_addr[16];        // dotted-quad "aaa.bbb.ccc.ddd"
};

struct MacAddr {
    char mac[48];            // book uses a 48-byte buffer (not 6); preserved
};

struct NodeNwProp {
    unsigned int flags;              // L3_ROUTER | L2_SWITCH | HUB
    bool         is_lb_addr_config;  // loopback configured?
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

static inline void init_node_nw_prop(NodeNwProp* p){
    p->flags             = 0;
    p->is_lb_addr_config = false;
    memset(p->lb_addr.ip_addr, 0, sizeof(p->lb_addr.ip_addr));
}

static inline void init_intf_nw_prop(IntfNwProps* p){
    memset(p->mac_add.mac, 0, sizeof(p->mac_add.mac));
    p->is_ipadd_config = false;
    memset(p->ip_add.ip_addr, 0, sizeof(p->ip_add.ip_addr));
    p->mask = 0;
}

// Lookup shortcuts. These touch full Node / Interface layouts, so
// callers must have graph.h included before using them.
#define IF_MAC(intf_ptr)        ((intf_ptr)->intf_nw_props.mac_add.mac)
#define IF_IP(intf_ptr)         ((intf_ptr)->intf_nw_props.ip_add.ip_addr)
#define NODE_LO_ADDR(node_ptr)  ((node_ptr)->node_nw_prop.lb_addr.ip_addr)

void interface_assign_mac_address(Interface* intf);

// Node-side setters.
bool node_set_device_type(Node* node, unsigned int flag);
bool node_set_loopback_address(Node* node, char* ip_addr);
bool node_set_intf_ip_address(Node* node, char* local_if, char* ip_addr, char mask);
bool node_unset_intf_ip_address(Node* node, char* local_if);

// Network-aware dumps. dump_graph from ch1 still works; these ones
// add device + IP + MAC lines.
void dump_nw_graph(Graph* graph);
void dump_node_nw_props(Node* node);
void dump_intf_props(Interface* intf);

#endif
