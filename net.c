#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "graph.h"
#include "net.h"

// Forward declarations.
void interface_assign_mac_address(Interface* intf);
bool node_set_device_type(Node* node, unsigned int flag);
bool node_set_loopback_address(Node* node, char* ip_addr);
bool node_set_intf_ip_address(Node* node, char* local_if, char* ip_addr, char mask);
bool node_unset_intf_ip_address(Node* node, char* local_if);
void dump_nw_graph(Graph* graph);
void dump_node_nw_props(Node* node);
void dump_intf_props(Interface* intf);

// Deterministic MAC heuristic: concatenate node name + interface
// name into the MAC byte buffer. Not a real OUI - just unique per
// (node, intf) pair so debugging is human-readable.
void interface_assign_mac_address(Interface* intf){
    memset(IF_MAC(intf), 0, sizeof(((MacAddr*)0)->mac));
    strcpy(IF_MAC(intf), intf->att_node->node_name);
    strcat(IF_MAC(intf), intf->if_name);
}

// SET_BIT / IS_BIT_SET take bit positions, but our L3_ROUTER /
// L2_SWITCH / HUB defines are already shifted (1 << N) values, so
// OR them in directly rather than translating to positions.
bool node_set_device_type(Node* node, unsigned int flag){
    node->node_nw_prop.flags |= flag;
    return true;
}

// Loopback only makes sense on an L3 device. The book asserts hard
// on misconfiguration; we keep that behaviour.
bool node_set_loopback_address(Node* node, char* ip_addr){
    bool ok = false;
    assert(ip_addr);
    if(node->node_nw_prop.flags & HUB){
        assert(0);  // HUBs have no IPs
    }
    if(!(node->node_nw_prop.flags & L3_ROUTER)){
        assert(0);  // enable L3 routing on the node first
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

// Network-aware Node dump. Adds the flags + loopback lines on top
// of the ch1 graph dump.
void dump_node_nw_props(Node* node){
    printf("\nNode Name = %s\n", node->node_name);
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
           (unsigned char)IF_MAC(intf)[0], (unsigned char)IF_MAC(intf)[1],
           (unsigned char)IF_MAC(intf)[2], (unsigned char)IF_MAC(intf)[3],
           (unsigned char)IF_MAC(intf)[4], (unsigned char)IF_MAC(intf)[5]);
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
