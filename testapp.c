#include <stdio.h>
#include "graph.h"

// Forward declarations.
extern Graph* build_first_topo(void);

int main(int argc, char** argv){
    (void)argc; (void)argv;
    Graph* topo = build_first_topo();
    dump_graph(topo);
    return 0;
}
