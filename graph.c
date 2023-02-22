#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "graph.h"

// Forward declarations.
Graph* create_new_graph(char* topology_name);
Node*  create_graph_node(Graph* graph, char* node_name);
void   insert_link_between_two_nodes(Node* node1, Node* node2,
                                     char* from_if_name, char* to_if_name,
                                     unsigned int cost);
void   dump_graph(Graph* graph);
void   dump_node(Node* node);
void   dump_interface(Interface* intf);

// ch4: bound when Nodes are created so the receiver thread can
// select() across all of them. Defined in comm.c.
extern void init_udp_socket(Node* node);

Graph* create_new_graph(char* topology_name){
    Graph* graph = calloc(1, sizeof(Graph));
    if(!graph){
        goto out;
    }
    strncpy(graph->topology_name, topology_name, TOPOLOGY_NAME_SIZE);
    graph->topology_name[TOPOLOGY_NAME_SIZE - 1] = '\0';
    init_glthread(&graph->node_list);
out:
    return graph;
}

Node* create_graph_node(Graph* graph, char* node_name){
    Node* node = calloc(1, sizeof(Node));
    if(!node){
        goto out;
    }
    strncpy(node->node_name, node_name, NODE_NAME_SIZE);
    node->node_name[NODE_NAME_SIZE - 1] = '\0';
    init_glthread(&node->graph_glue);
    glthread_add_next(&graph->node_list, &node->graph_glue);
    // ch2: zero the L3 properties (loopback off, no device-type flags).
    init_node_nw_prop(&node->node_nw_prop);
    // ch4: bring up the Node's UDP socket so the simulator can
    // route packets to it.
    init_udp_socket(node);
out:
    return node;
}

// Link both endpoints to one shared Link, and slot each endpoint
// into the first free interface slot on its owning Node.
void insert_link_between_two_nodes(Node* node1, Node* node2,
                                   char* from_if_name, char* to_if_name,
                                   unsigned int cost){
    Link* link = calloc(1, sizeof(Link));
    if(!link){
        return;
    }

    strncpy(link->intf1.if_name, from_if_name, IF_NAME_SIZE);
    link->intf1.if_name[IF_NAME_SIZE - 1] = '\0';
    strncpy(link->intf2.if_name, to_if_name,   IF_NAME_SIZE);
    link->intf2.if_name[IF_NAME_SIZE - 1] = '\0';

    link->intf1.link = link;
    link->intf2.link = link;
    link->intf1.att_node = node1;
    link->intf2.att_node = node2;
    link->cost           = cost;

    int slot1 = get_node_intf_available_slot(node1);
    int slot2 = get_node_intf_available_slot(node2);
    if(slot1 == -1 || slot2 == -1){
        free(link);
        return;
    }
    node1->intf[slot1] = &link->intf1;
    node2->intf[slot2] = &link->intf2;

    // ch2: zero L3 props on both endpoints and stamp a deterministic
    // MAC built from the owning node + interface names.
    init_intf_nw_prop(&link->intf1.intf_nw_props);
    init_intf_nw_prop(&link->intf2.intf_nw_props);
    interface_assign_mac_address(&link->intf1);
    interface_assign_mac_address(&link->intf2);
}

void dump_interface(Interface* intf){
    Link* link = intf->link;
    Node* nbr  = get_nbr_node(intf);
    printf("    Local Node : %s, Interface Name : %s, Nbr Node %s, cost = %u\n",
           intf->att_node->node_name, intf->if_name, nbr->node_name, link->cost);
}

void dump_node(Node* node){
    printf("Node Name = %s :\n", node->node_name);
    for(int i = 0; i < MAX_INTF_PER_NODE; i++){
        if(!node->intf[i]){
            break;
        }
        dump_interface(node->intf[i]);
    }
}

void dump_graph(Graph* graph){
    printf("Topology Name = %s\n", graph->topology_name);
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&graph->node_list, cur){
        Node* node = graph_glue_to_node(cur);
        dump_node(node);
    } ITERATE_GLTHREAD_END(&graph->node_list, cur);
}
