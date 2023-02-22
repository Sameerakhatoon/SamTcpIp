#ifndef SAMTCPIP_CLI_H
#define SAMTCPIP_CLI_H

// Tiny command-tree CLI. Each command is a node in a tree of CliCmd;
// leaves carry a handler. The parser tokenizes a line by whitespace,
// walks the tree token-by-token, captures placeholder tokens as
// argv entries, and invokes the matched handler.
//
// Design rules:
//   - One static tree per app, built at startup via cli_set_root.
//   - Each CliCmd lists its children as a NULL-terminated array.
//   - A `capture` child means "the current token is a value, store
//     it"; otherwise the token must literally equal child->name.
//   - At most one `capture` child per level - if you need more, name
//     them with literal selector keywords (e.g. `port <id>` plus
//     `vlan <id>` rather than two bare captures).

#include <stdbool.h>
#include <stdio.h>

#define CLI_MAX_ARGS    16
#define CLI_LINE_BUF    512

typedef struct CliCmd CliCmd;

// argc / argv are the captured placeholder values, in the order
// they appeared on the command line.
typedef int (*CliHandler)(int argc, char** argv);

struct CliCmd {
    const char*  name;       // literal token, or display name like "<node-name>" for captures
    bool         capture;    // true: any token at this slot is captured into argv
    CliHandler   handler;    // invoked when the walk lands here with no more tokens
    const char*  help;
    CliCmd**     children;   // NULL-terminated; may be NULL on a pure leaf
};

void cli_set_root(CliCmd* root);
int  cli_run_line(const char* line);    // 0 on success, non-zero on parse/handler error
void cli_repl(FILE* in);                // line-by-line read loop, prints prompt

#endif
