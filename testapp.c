#include <stdio.h>
#include <string.h>
#include "cli.h"
#include "graph.h"
#include "net.h"
#include "nwcli.h"

// Forward declarations.
extern Graph* build_first_topo(void);
extern Graph* build_simple_l2_switch_topo(void);
extern Graph* build_vlan_l2_switch_topo(void);

// testapp boots the topology, installs the CLI tree, and either
// runs `--cmd "<line>"` (single-shot for tests) or drops into a
// stdin REPL. ch6/7 added `--topo l2switch` / `--topo vlan` to pick
// alternative topologies instead of the default 3-node ring.
int main(int argc, char** argv){
    Graph* topo        = 0;
    const char* topo_name = "first";
    int    i           = 1;

    // First parse optional `--topo <name>` from the front of argv.
    if(argc >= 3 && strcmp(argv[1], "--topo") == 0){
        topo_name = argv[2];
        i = 3;
    }
    if(strcmp(topo_name, "l2switch") == 0){
        topo = build_simple_l2_switch_topo();
    } else if(strcmp(topo_name, "vlan") == 0){
        topo = build_vlan_l2_switch_topo();
    } else {
        topo = build_first_topo();
    }

    nwcli_install(topo);

    if(i + 1 < argc && strcmp(argv[i], "--cmd") == 0){
        return cli_run_line(argv[i + 1]);
    }
    cli_repl(stdin);
    return 0;
}
