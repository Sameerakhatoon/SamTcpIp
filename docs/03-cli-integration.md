# ch3 - CLI integration

Adds a tiny hand-rolled command-tree CLI. No external dependency:
the reference repo vendors a 1000+ LOC `libcli`; we wrote a single
`cli.h` / `cli.c` (~120 LOC) that does what we need and nothing
else.

## Why roll our own

- We do not need bash-style history, tab completion, or negation
  operators ("no shutdown") today. Future chapters can extend.
- The parser is the only part the tests touch, so it has to be
  scriptable from a bash test - which means `--cmd "..."` and a
  stdin REPL. Both are trivial to add to our own walker.
- Vendoring a third-party tree pulls in its assumptions about
  tokenization, TLV buffers, op_modes etc. We can grow into those
  features only if and when a command actually needs them.

## Tree shape

Each `CliCmd` is a node:

```
struct CliCmd {
    const char*  name;       // literal token like "show", or display
                             // text like "<node-name>" for captures
    bool         capture;    // true: any token at this slot is
                             //       captured into argv[]
    CliHandler   handler;    // run when walk lands here with no
                             // more tokens
    const char*  help;
    CliCmd**     children;   // NULL-terminated; NULL on leaves
};
```

Children are arranged NULL-terminated so adding a sibling means
editing one array. Capture is an at-most-one fallback at each level:
the walker first looks for a literal-name match, then falls back to
the capture child and records the token. This keeps `show node X
arp` parsable without ambiguity ("X" goes into argv).

## Walker

```
walk(cur, tokens, n, tok_idx, argv, argc)
    if tok_idx == n:        invoke cur->handler(argc, argv)
    if cur->children == 0:  error "extra tokens after `cur->name`"
    for each child:
      if not capture and name == tokens[tok_idx]: recurse
    if a capture child was seen: argv[argc++] = tok, recurse
    else: error "unknown token `tok`"
```

Errors print to stderr and return non-zero so the bash tests can
distinguish parse failure from handler failure.

## REPL + single-shot

`testapp` now has two modes:

- `./testapp --cmd "<line>"` runs one command, exits with that
  command's return code. This is what the tests use.
- `./testapp` with no args drops into a stdin REPL with a
  `samtcpip> ` prompt. Useful for hand-debug. Quits on `quit` or
  EOF.

The CLI tree for ch3 is just:

```
<root>
  show
    topology   -> show_topology_handler -> dump_nw_graph
```

Later chapters will add `show node <name> arp`, `show node <name>
mac`, `run node <name> resolve-arp <ip>`, and so on.

## Tests touched

- `tests/01-graph-build.sh` and `tests/02-network-props.sh` were
  driven by `./testapp` printing the topology on startup; ch3 moved
  that behind `show topology` so both tests now pass
  `--cmd 'show topology'`.
- `tests/03-cli-show-topology.sh` covers four cases:
  - `--cmd 'show topology'` dispatches the handler.
  - Unknown token (`wibble`) -> non-zero exit + "unknown token" on
    stderr.
  - Incomplete command (`show`) -> non-zero exit + "incomplete
    command" on stderr.
  - REPL: `printf 'show topology\nquit\n' | ./testapp` runs the
    same handler.
