#include "graph.h"

// Forward declarations.
Graph* build_first_topo(void);

// First topology: a 3-node ring used to smoke-test the graph layer.
//
//      eth0/0          eth0/1
//   R0 ------- link -------- R1
//   eth0/4                eth0/2
//        \              /
//         eth0/5  eth0/3
//             R2
//
Graph* build_first_topo(void){
    Graph* topo = create_new_graph("Hello World Generic Graph");
    Node*  r0   = create_graph_node(topo, "R0_re");
    Node*  r1   = create_graph_node(topo, "R1_re");
    Node*  r2   = create_graph_node(topo, "R2_re");

    insert_link_between_two_nodes(r0, r1, "eth0/0", "eth0/1", 1);
    insert_link_between_two_nodes(r1, r2, "eth0/2", "eth0/3", 1);
    insert_link_between_two_nodes(r0, r2, "eth0/4", "eth0/5", 1);
    return topo;
}
