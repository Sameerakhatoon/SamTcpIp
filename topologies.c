#include "graph.h"
#include "net.h"

// Forward declarations.
Graph* build_first_topo(void);

// First topology: a 3-node L3 ring used to smoke-test both the
// graph layer and the ch2 network-properties layer.
//
//                  +----------+
//              0/4 |          | 0/0
//      +-----------+   R0_re  +-------------+
//      | 40.1.1.1/24| 122.1.1.0|20.1.1.1/24 |
//      |           +-----------+            |
//      |                                    |
//      |40.1.1.2/24                         |20.1.1.2/24
//      | 0/5                                | 0/1
//   +--+--+                              +--+--+
//   |     | 0/3                       0/2|     |
//   |R2_re+-----------------------------+R1_re|
//   |     | 30.1.1.2/24      30.1.1.1/24|     |
//   +-----+                              +-----+
//
Graph* build_first_topo(void){
    Graph* topo  = create_new_graph("Hello World Generic Graph");
    Node*  r0_re = create_graph_node(topo, "R0_re");
    Node*  r1_re = create_graph_node(topo, "R1_re");
    Node*  r2_re = create_graph_node(topo, "R2_re");

    insert_link_between_two_nodes(r0_re, r1_re, "eth0/0", "eth0/1", 1);
    insert_link_between_two_nodes(r1_re, r2_re, "eth0/2", "eth0/3", 1);
    insert_link_between_two_nodes(r0_re, r2_re, "eth0/4", "eth0/5", 1);

    node_set_device_type(r0_re, L3_ROUTER);
    node_set_loopback_address(r0_re, "122.1.1.0");
    node_set_intf_ip_address(r0_re, "eth0/4", "40.1.1.1", 24);
    node_set_intf_ip_address(r0_re, "eth0/0", "20.1.1.1", 24);

    node_set_device_type(r1_re, L3_ROUTER);
    node_set_loopback_address(r1_re, "122.1.1.1");
    node_set_intf_ip_address(r1_re, "eth0/1", "20.1.1.2", 24);
    node_set_intf_ip_address(r1_re, "eth0/2", "30.1.1.1", 24);

    node_set_device_type(r2_re, L3_ROUTER);
    node_set_loopback_address(r2_re, "122.1.1.2");
    node_set_intf_ip_address(r2_re, "eth0/3", "30.1.1.2", 24);
    node_set_intf_ip_address(r2_re, "eth0/5", "40.1.1.2", 24);

    return topo;
}
