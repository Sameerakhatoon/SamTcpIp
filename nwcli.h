#ifndef SAMTCPIP_NWCLI_H
#define SAMTCPIP_NWCLI_H

// Network-aware CLI wiring: builds the command tree and registers
// it with the generic CLI. testapp.c calls nwcli_install before
// driving the REPL.

#include "graph.h"

void nwcli_install(Graph* topo);

#endif
