#!/usr/bin/env bash
# Ch3: CLI parser dispatches "show topology" to the dump handler.
# Also exercises the unknown-token error path and the REPL stdin
# driver so we know the command-tree walk works end-to-end.
. "$(dirname "$0")/lib.sh"

# 1. --cmd single-shot dispatches the registered handler.
out="$(./testapp --cmd 'show topology')"
assert_contains "$out" "Topology Name = Hello World Generic Graph" "show topology dispatched"
assert_contains "$out" "Node Name = R0_re" "R0 in dump"

# 2. Unknown token at the top level prints an error and exits non-zero.
if ./testapp --cmd 'wibble' >/tmp/_out 2>/tmp/_err; then
    fail "expected non-zero exit for unknown command, got 0"
fi
err="$(cat /tmp/_err)"
rm -f /tmp/_out /tmp/_err
assert_contains "$err" "unknown token" "rejects unknown token"

# 3. Incomplete command (parent with no leaf reached) errors out.
if ./testapp --cmd 'show' >/tmp/_out 2>/tmp/_err; then
    fail "expected non-zero exit for incomplete command, got 0"
fi
err2="$(cat /tmp/_err)"
rm -f /tmp/_out /tmp/_err
assert_contains "$err2" "incomplete command" "rejects incomplete command"

# 4. REPL reads stdin line by line.
out2="$(printf 'show topology\nquit\n' | ./testapp)"
assert_contains "$out2" "Topology Name = Hello World Generic Graph" "REPL ran show topology"
pass
