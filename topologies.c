#include "Layer2/layer2.h"
#include "graph.h"
#include "net.h"

// Forward declarations.
Graph* build_first_topo(void);
Graph* build_simple_l2_switch_topo(void);

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

// ch6: 3 hosts hanging off one L2 switch. All three switch-side
// ports run in ACCESS mode so the switch learns + forwards by MAC.
// Hosts share 10.1.1.0/24 so ARP requests cross the switch
// transparently.
//
//        H1 (10.1.1.1/24)
//        eth0/4
//          |
//          | eth0/5 (access)
//          |
//        L2SW -- eth0/7 (access) -- eth0/6 H2 (10.1.1.2/24)
//          |
//          | eth0/8 (access)
//          |
//        eth0/1
//        H4 (10.1.1.4/24)
//
Graph* build_simple_l2_switch_topo(void){
    Graph* topo = create_new_graph("Simple L2 Switch Topology");
    Node*  h1   = create_graph_node(topo, "H1");
    Node*  h2   = create_graph_node(topo, "H2");
    Node*  h4   = create_graph_node(topo, "H4");
    Node*  sw   = create_graph_node(topo, "L2SW");

    insert_link_between_two_nodes(h1, sw, "eth0/4", "eth0/5", 1);
    insert_link_between_two_nodes(h2, sw, "eth0/6", "eth0/7", 1);
    insert_link_between_two_nodes(h4, sw, "eth0/1", "eth0/8", 1);

    node_set_device_type(h1, L3_ROUTER);
    node_set_loopback_address(h1, "122.1.1.1");
    node_set_intf_ip_address(h1, "eth0/4", "10.1.1.1", 24);

    node_set_device_type(h2, L3_ROUTER);
    node_set_loopback_address(h2, "122.1.1.2");
    node_set_intf_ip_address(h2, "eth0/6", "10.1.1.2", 24);

    node_set_device_type(h4, L3_ROUTER);
    node_set_loopback_address(h4, "122.1.1.4");
    node_set_intf_ip_address(h4, "eth0/1", "10.1.1.4", 24);

    node_set_device_type(sw, L2_SWITCH);
    node_set_intf_l2_mode(sw, "eth0/5", ACCESS);
    node_set_intf_l2_mode(sw, "eth0/7", ACCESS);
    node_set_intf_l2_mode(sw, "eth0/8", ACCESS);

    return topo;
}
