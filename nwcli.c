#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "comm.h"
#include "graph.h"
#include "net.h"
#include "nwcli.h"

// Forward declarations.
static Node* find_node_by_name(const char* name);
static int   show_topology_handler(int argc, char** argv);
static int   run_send_handler(int argc, char** argv);
void         nwcli_install(Graph* topo);

// The CLI tree only ever needs a single Graph (the topology built at
// startup); stash it so handlers do not need argv.
static Graph* g_topo = 0;

static Node* find_node_by_name(const char* name){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_topo->node_list, cur){
        Node* n = graph_glue_to_node(cur);
        if(strncmp(n->node_name, name, NODE_NAME_SIZE) == 0){
            return n;
        }
    } ITERATE_GLTHREAD_END(&g_topo->node_list, cur);
    return 0;
}

static int show_topology_handler(int argc, char** argv){
    (void)argc; (void)argv;
    if(!g_topo){
        fprintf(stderr, "no topology installed\n");
        return 1;
    }
    dump_nw_graph(g_topo);
    return 0;
}

// ch4: `run send <node> <if> <payload>` - look up the named Node
// and Interface, push the payload out through it. Sleep briefly
// after so the (detached) receiver thread can print before the
// CLI returns to the caller.
static int run_send_handler(int argc, char** argv){
    if(argc != 3){
        fprintf(stderr, "run send: expected <node> <if> <payload>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    Interface* oif = get_node_if_by_name(node, argv[1]);
    if(!oif){
        fprintf(stderr, "no such interface `%s` on node `%s`\n", argv[1], argv[0]);
        return 1;
    }
    int rc = send_pkt_out(argv[2], strlen(argv[2]) + 1, oif);
    if(rc < 0){
        fprintf(stderr, "send_pkt_out failed (rc=%d)\n", rc);
        return 1;
    }
    // Give the receiver thread a moment to dispatch + print.
    usleep(100 * 1000);
    return 0;
}

// Children arrays are NULL-terminated. Built bottom-up so each
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

// run send <node> <if> <payload>: three trailing tokens captured.
static CliCmd cmd_run_send_payload = {
    .name     = "<payload>",
    .capture  = true,
    .handler  = run_send_handler,
    .help     = "payload bytes (cstring)",
};
static CliCmd* run_send_payload_children[] = { &cmd_run_send_payload, 0 };

static CliCmd cmd_run_send_if = {
    .name     = "<if-name>",
    .capture  = true,
    .help     = "interface name (e.g. eth0/0)",
    .children = run_send_payload_children,
};
static CliCmd* run_send_if_children[] = { &cmd_run_send_if, 0 };

static CliCmd cmd_run_send_node = {
    .name     = "<node-name>",
    .capture  = true,
    .help     = "node name (e.g. R0_re)",
    .children = run_send_if_children,
};
static CliCmd* run_send_node_children[] = { &cmd_run_send_node, 0 };

static CliCmd cmd_run_send = {
    .name     = "send",
    .help     = "send <node> <if> <payload>: emit a packet out an intf",
    .children = run_send_node_children,
};

static CliCmd* run_children[] = {
    &cmd_run_send,
    0,
};

static CliCmd cmd_run = {
    .name     = "run",
    .help     = "run: perform live actions",
    .children = run_children,
};

static CliCmd* root_children[] = {
    &cmd_show,
    &cmd_run,
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
    // ch4: bring up the per-Node receiver thread so commands like
    // `run send ...` have a working forwarding path.
    network_start_pkt_receiver_thread(topo);
    // Give the thread a beat to call FD_SET on every socket before
    // the first send.
    usleep(50 * 1000);
}
