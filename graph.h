#ifndef SAMTCPIP_GRAPH_H
#define SAMTCPIP_GRAPH_H

// Generic static graph used to model the network topology. Graph
// holds a list of Node; each Node has up to MAX_INTF_PER_NODE
// Interface slots; each Interface knows its owning Node and the
// Link it is wired to; a Link is two Interfaces plus a cost.
//
// Networking properties (MAC, IP, mask) layer on top in later
// chapters via separate per-Node and per-Interface nw_props.

#include <assert.h>
#include "gluethread/glthread.h"
#include "net.h"           // ch2: pulls in NodeNwProp + IntfNwProps

#define NODE_NAME_SIZE      16
#define IF_NAME_SIZE        16
#define MAX_INTF_PER_NODE   10
#define TOPOLOGY_NAME_SIZE  32

typedef struct Link Link;

struct Interface {
    char        if_name[IF_NAME_SIZE];
    Node*       att_node;
    Link*       link;
    IntfNwProps intf_nw_props;       // ch2
};

struct Link {
    Interface    intf1;
    Interface    intf2;
    unsigned int cost;
};

struct Node {
    char       node_name[NODE_NAME_SIZE];
    Interface* intf[MAX_INTF_PER_NODE];
    GlThread   graph_glue;           // hangs on Graph.node_list
    NodeNwProp node_nw_prop;         // ch2
};

GLTHREAD_TO_STRUCT(graph_glue_to_node, Node, graph_glue);

struct Graph {
    char     topology_name[TOPOLOGY_NAME_SIZE];
    GlThread node_list;
};

Graph* create_new_graph(char* topology_name);
Node*  create_graph_node(Graph* graph, char* node_name);
void   insert_link_between_two_nodes(Node* node1, Node* node2,
                                     char* from_if_name, char* to_if_name,
                                     unsigned int cost);

// Walk from an Interface to its peer Node across the Link.
static inline Node* get_nbr_node(Interface* intf){
    assert(intf->att_node);
    assert(intf->link);
    Link* link = intf->link;
    if(&link->intf1 == intf){
        return link->intf2.att_node;
    }
    return link->intf1.att_node;
}

static inline int get_node_intf_available_slot(Node* node){
    for(int i = 0; i < MAX_INTF_PER_NODE; i++){
        if(node->intf[i]){
            continue;
        }
        return i;
    }
    return -1;
}

// ch2: lookup an Interface by its short name ("eth0/0"). Used by
// node_set_intf_ip_address. Returns 0 when not found.
static inline Interface* get_node_if_by_name(Node* node, char* if_name){
    for(int i = 0; i < MAX_INTF_PER_NODE; i++){
        Interface* intf = node->intf[i];
        if(!intf){
            return 0;
        }
        if(strncmp(intf->if_name, if_name, IF_NAME_SIZE) == 0){
            return intf;
        }
    }
    return 0;
}

void dump_graph(Graph* graph);
void dump_node(Node* node);
void dump_interface(Interface* intf);

#endif
