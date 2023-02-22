#include <stdio.h>
#include "graph.h"
#include "net.h"

// Forward declarations.
extern Graph* build_first_topo(void);

int main(int argc, char** argv){
    (void)argc; (void)argv;
    Graph* topo = build_first_topo();
    // ch2: dump the network-aware view (loopback / IP / MAC) instead
    // of the bare graph dump from ch1.
    dump_nw_graph(topo);
    return 0;
}
