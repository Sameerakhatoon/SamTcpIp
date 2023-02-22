#include <stdio.h>
#include <string.h>
#include "cli.h"

// Forward declarations.
static int  tokenize(char* buf, char** tokens, int max_tokens);
static int  walk(CliCmd* cur, char** tokens, int n_tokens,
                 int tok_idx, char** argv, int argc);
void        cli_set_root(CliCmd* root);
int         cli_run_line(const char* line);
void        cli_repl(FILE* in);

static CliCmd* g_root = 0;

void cli_set_root(CliCmd* root){
    g_root = root;
}

// Split buf in place on whitespace; nul-terminate each token and
// store its start in tokens[]. Returns the token count.
static int tokenize(char* buf, char** tokens, int max_tokens){
    int   n = 0;
    char* p = buf;
    while(*p && n < max_tokens){
        while(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'){
            *p++ = '\0';
        }
        if(!*p){
            break;
        }
        tokens[n++] = p;
        while(*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r'){
            p++;
        }
    }
    return n;
}

// Recursive walk. At each level we look for the FIRST literal-match
// child; if none, fall back to the (at most one) capture child and
// record the token. When we run out of tokens, invoke the handler.
static int walk(CliCmd* cur, char** tokens, int n_tokens,
                int tok_idx, char** argv, int argc){
    if(tok_idx == n_tokens){
        if(!cur->handler){
            fprintf(stderr, "incomplete command\n");
            return 1;
        }
        return cur->handler(argc, argv);
    }
    if(!cur->children){
        fprintf(stderr, "extra tokens after `%s`\n", cur->name);
        return 1;
    }
    char*   tok      = tokens[tok_idx];
    CliCmd* capt     = 0;
    for(CliCmd** cp = cur->children; *cp; cp++){
        CliCmd* child = *cp;
        if(child->capture){
            // Remember a capture-fallback in case no literal matches.
            if(!capt){
                capt = child;
            }
            continue;
        }
        if(strcmp(child->name, tok) == 0){
            return walk(child, tokens, n_tokens, tok_idx + 1, argv, argc);
        }
    }
    if(capt){
        if(argc >= CLI_MAX_ARGS){
            fprintf(stderr, "too many arguments\n");
            return 1;
        }
        argv[argc++] = tok;
        return walk(capt, tokens, n_tokens, tok_idx + 1, argv, argc);
    }
    fprintf(stderr, "unknown token `%s`\n", tok);
    return 1;
}

int cli_run_line(const char* line){
    if(!g_root){
        fprintf(stderr, "cli: no root command set\n");
        return 1;
    }
    char  buf[CLI_LINE_BUF];
    char* tokens[CLI_MAX_ARGS];
    char* argv[CLI_MAX_ARGS];

    strncpy(buf, line, CLI_LINE_BUF);
    buf[CLI_LINE_BUF - 1] = '\0';

    int n = tokenize(buf, tokens, CLI_MAX_ARGS);
    if(n == 0){
        return 0;
    }
    return walk(g_root, tokens, n, 0, argv, 0);
}

// Minimal REPL. Prompt, read a line, dispatch. Quits on EOF or "quit".
void cli_repl(FILE* in){
    char line[CLI_LINE_BUF];
    for(;;){
        if(in == stdin){
            fputs("samtcpip> ", stdout);
            fflush(stdout);
        }
        if(!fgets(line, sizeof(line), in)){
            break;
        }
        if(strncmp(line, "quit", 4) == 0){
            break;
        }
        cli_run_line(line);
    }
}
