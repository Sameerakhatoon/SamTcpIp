#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "graph.h"
#include "net.h"
#include "utils.h"

// Forward declarations.
static unsigned int hash_code(void* ptr, unsigned int size);
void                init_node_nw_prop(NodeNwProp* p);
void                init_intf_nw_prop(IntfNwProps* p);
void                interface_assign_mac_address(Interface* intf);
bool                node_set_device_type(Node* node, unsigned int flag);
bool                node_set_loopback_address(Node* node, char* ip_addr);
bool                node_set_intf_ip_address(Node* node, char* local_if, char* ip_addr, char mask);
bool                node_unset_intf_ip_address(Node* node, char* local_if);
Interface*          node_get_matching_subnet_interface(Node* node, char* ip_addr);
void                dump_nw_graph(Graph* graph);
void                dump_node_nw_props(Node* node);
void                dump_intf_props(Interface* intf);

// ch5/ch6: opaque-friendly init. The full ArpTable / MacTable
// types live in Layer2/layer2.h; these trampolines keep net.c
// free of layer2 includes.
extern void init_arp_table(ArpTable** arp_table);
extern void init_mac_table(MacTable** mac_table);

// Cheap multiplicative hash used to derive a 4-byte MAC seed from
// any pointer's content. Not a real OUI - just stable-within-a-run
// + unique per interface so debug output is recognisable.
static unsigned int hash_code(void* ptr, unsigned int size){
    unsigned int value = 0;
    char*        str   = (char*)ptr;
    for(unsigned int i = 0; i < size; i++){
        value += (unsigned char)*str;
        value *= 97;
        str++;
    }
    return value;
}

void init_node_nw_prop(NodeNwProp* p){
    p->flags             = 0;
    p->is_lb_addr_config = false;
    memset(p->lb_addr.ip_addr, 0, sizeof(p->lb_addr.ip_addr));
    // ch5: every Node gets an empty ARP table at creation time.
    init_arp_table(&p->arp_table);
    // ch6: and an empty mac-learning table.
    init_mac_table(&p->mac_table);
}

void init_intf_nw_prop(IntfNwProps* p){
    // L2.
    memset(p->mac_add.mac, 0, sizeof(p->mac_add.mac));
    p->intf_l2_mode = L2_MODE_UNKNOWN;
    memset(p->vlans, 0, sizeof(p->vlans));
    p->is_ipadd_config_backup = false;
    // L3.
    p->is_ipadd_config = false;
    memset(p->ip_add.ip_addr, 0, sizeof(p->ip_add.ip_addr));
    p->mask = 0;
}

// ch5: with MacAddr shrunk to 6 bytes, the ch2 "concat name into
// MAC" heuristic no longer fits. Hash the Interface*'s content into
// a 4-byte seed and pad to 6.
void interface_assign_mac_address(Interface* intf){
    unsigned int seed = hash_code(intf, sizeof(*intf));
    memset(IF_MAC(intf), 0, 6);
    memcpy(IF_MAC(intf), &seed, sizeof(unsigned int));
}

bool node_set_device_type(Node* node, unsigned int flag){
    node->node_nw_prop.flags |= flag;
    return true;
}

bool node_set_loopback_address(Node* node, char* ip_addr){
    bool ok = false;
    assert(ip_addr);
    if(node->node_nw_prop.flags & HUB){
        assert(0);
    }
    if(!(node->node_nw_prop.flags & L3_ROUTER)){
        assert(0);
    }
    node->node_nw_prop.is_lb_addr_config = true;
    strncpy(NODE_LO_ADDR(node), ip_addr, 15);
    NODE_LO_ADDR(node)[15] = '\0';
    ok = true;
    return ok;
}

bool node_set_intf_ip_address(Node* node, char* local_if, char* ip_addr, char mask){
    bool       ok   = false;
    Interface* intf = get_node_if_by_name(node, local_if);
    if(!intf){
        goto out;
    }
    strncpy(IF_IP(intf), ip_addr, 15);
    IF_IP(intf)[15] = '\0';
    intf->intf_nw_props.mask           = mask;
    intf->intf_nw_props.is_ipadd_config = true;
    ok = true;
out:
    return ok;
}

bool node_unset_intf_ip_address(Node* node, char* local_if){
    Interface* intf = get_node_if_by_name(node, local_if);
    if(!intf){
        return false;
    }
    memset(IF_IP(intf), 0, 16);
    intf->intf_nw_props.mask           = 0;
    intf->intf_nw_props.is_ipadd_config = false;
    return true;
}

// ch5: walk the Node's interfaces; apply each interface's mask to
// both its own IP and the lookup IP; the first matching pair is the
// owning subnet.
Interface* node_get_matching_subnet_interface(Node* node, char* ip_addr){
    char intf_subnet[16];
    char lookup_subnet[16];
    for(int i = 0; i < MAX_INTF_PER_NODE; i++){
        Interface* intf = node->intf[i];
        if(!intf){
            return 0;
        }
        if(!intf->intf_nw_props.is_ipadd_config){
            continue;
        }
        memset(intf_subnet,   0, sizeof(intf_subnet));
        memset(lookup_subnet, 0, sizeof(lookup_subnet));
        apply_mask(IF_IP(intf), intf->intf_nw_props.mask, intf_subnet);
        apply_mask(ip_addr,     intf->intf_nw_props.mask, lookup_subnet);
        if(strncmp(intf_subnet, lookup_subnet, 16) == 0){
            return intf;
        }
    }
    return 0;
}

void dump_node_nw_props(Node* node){
    printf("\nNode Name = %s, udp_port_no = %u\n", node->node_name, node->udp_port_number);
    printf("\t node flags : %u\n", node->node_nw_prop.flags);
    if(node->node_nw_prop.is_lb_addr_config){
        printf("\t  lo addr : %s/32\n", NODE_LO_ADDR(node));
    }
}

void dump_intf_props(Interface* intf){
    dump_interface(intf);
    if(intf->intf_nw_props.is_ipadd_config){
        printf("\t IP Addr = %s/%u", IF_IP(intf), intf->intf_nw_props.mask);
    } else {
        printf("\t IP Addr = %s/%u", "Nil", 0);
    }
    printf("\t MAC : %u:%u:%u:%u:%u:%u\n",
           intf->intf_nw_props.mac_add.mac[0], intf->intf_nw_props.mac_add.mac[1],
           intf->intf_nw_props.mac_add.mac[2], intf->intf_nw_props.mac_add.mac[3],
           intf->intf_nw_props.mac_add.mac[4], intf->intf_nw_props.mac_add.mac[5]);
}

void dump_nw_graph(Graph* graph){
    GlThread* curr = 0;
    printf("Topology Name = %s\n", graph->topology_name);
    ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){
        Node* node = graph_glue_to_node(curr);
        dump_node_nw_props(node);
        for(int i = 0; i < MAX_INTF_PER_NODE; i++){
            Interface* intf = node->intf[i];
            if(!intf){
                break;
            }
            dump_intf_props(intf);
        }
    } ITERATE_GLTHREAD_END(&graph->node_list, curr);
}
