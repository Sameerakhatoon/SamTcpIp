#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "graph.h"
#include "net.h"
#include "nwcli.h"
#include "pcap.h"
#include "tap.h"

// Forward declarations.
extern Graph* build_first_topo(void);
extern Graph* build_simple_l2_switch_topo(void);
extern Graph* build_vlan_l2_switch_topo(void);

// ch36: clean-shutdown handler. On SIGINT (Ctrl-C) or SIGTERM,
// release the TAP fd (if attached), flush + close any active
// pcap, and exit cleanly. Without this, the kernel TAP interface
// can linger past process death and pcap files stay truncated.
static void on_signal(int signo){
    // stdout is block-buffered when redirected to a non-terminal;
    // explicit fflush so the goodbye line survives _exit.
    printf("\nReceived signal %d - shutting down cleanly\n", signo);
    fflush(stdout);
    tap_detach();
    pcap_close_file();
    // Use _exit so atexit handlers (none today) don't fire. We've
    // already cleaned up everything that matters.
    _exit(0);
}

static void install_signal_handlers(void){
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

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

    // ch36: install AFTER nwcli_install so the handler can rely on
    // the topology + module state existing if it ever needs them.
    install_signal_handlers();

    if(i + 1 < argc && strcmp(argv[i], "--cmd") == 0){
        return cli_run_line(argv[i + 1]);
    }
    cli_repl(stdin);
    return 0;
}
