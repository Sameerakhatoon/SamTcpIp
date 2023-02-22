#include <stdio.h>
#include <string.h>
#include "cli.h"
#include "graph.h"
#include "net.h"
#include "nwcli.h"

// Forward declarations.
extern Graph* build_first_topo(void);

// testapp now boots the topology, installs the CLI tree, and either
//   - runs `--cmd "<line>"` for a single non-interactive shot, or
//   - reads stdin line-by-line for an interactive REPL.
// The single-shot mode is what the bash tests drive.
int main(int argc, char** argv){
    Graph* topo = build_first_topo();
    nwcli_install(topo);

    if(argc >= 3 && strcmp(argv[1], "--cmd") == 0){
        return cli_run_line(argv[2]);
    }
    cli_repl(stdin);
    return 0;
}
