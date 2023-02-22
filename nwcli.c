#include <stdio.h>
#include "cli.h"
#include "graph.h"
#include "net.h"
#include "nwcli.h"

// Forward declarations.
static int show_topology_handler(int argc, char** argv);
void       nwcli_install(Graph* topo);

// The CLI tree only ever needs a single Graph (the topology built at
// startup); stash it so handlers do not need argv.
static Graph* g_topo = 0;

static int show_topology_handler(int argc, char** argv){
    (void)argc; (void)argv;
    if(!g_topo){
        fprintf(stderr, "no topology installed\n");
        return 1;
    }
    dump_nw_graph(g_topo);
    return 0;
}

// Children arrays are NULL-terminated. Building bottom-up so each
// parent's child pointer table is in scope.

static CliCmd cmd_show_topology = {
    .name     = "topology",
    .handler  = show_topology_handler,
    .help     = "dump the loaded topology with L2/L3 properties",
};

static CliCmd* show_children[] = {
    &cmd_show_topology,
    0,
};

static CliCmd cmd_show = {
    .name     = "show",
    .help     = "show: inspect runtime state",
    .children = show_children,
};

static CliCmd* root_children[] = {
    &cmd_show,
    0,
};

static CliCmd cmd_root = {
    .name     = "<root>",
    .help     = "root",
    .children = root_children,
};

void nwcli_install(Graph* topo){
    g_topo = topo;
    cli_set_root(&cmd_root);
}
