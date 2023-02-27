#!/usr/bin/env bash
# Ch8: L3 routing table. Two paths covered:
#   1. Auto-installed direct routes: setting an interface IP or
#      loopback installs the corresponding directly-connected route.
#   2. Static routes via CLI: `config node <n> route <p> <m> <gw> <oif>`.
# Plus `show node <n> route` for inspection.
. "$(dirname "$0")/lib.sh"

# 1. Default topology: R0_re has loopback 122.1.1.0/32 and two L3
#    interfaces in 20.1.1.0/24 and 40.1.1.0/24. show route should
#    list all three directly-connected entries.
out_auto="$(./testapp --cmd 'show node R0_re route')"
assert_contains "$out_auto" "L3 Routing Table:" "header line"
assert_contains "$out_auto" "20.1.1.0           24"  "R0_re eth0/0 subnet auto-installed"
assert_contains "$out_auto" "40.1.1.0           24"  "R0_re eth0/4 subnet auto-installed"
assert_contains "$out_auto" "122.1.1.0          32"  "R0_re loopback /32 auto-installed"

# 2. Install a static route via the REPL and verify show.
out_static="$(printf 'config node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0\nshow node R0_re route\nquit\n' | ./testapp)"
assert_contains "$out_static" "30.1.1.0           24   20.1.1.2           eth0/0" "static route 30.1.1.0/24 via 20.1.1.2"

# 3. Direct route via CLI (`direct` token -> is_direct = true).
out_direct="$(printf 'config node R0_re route 50.50.50.0 24 direct -\nshow node R0_re route\nquit\n' | ./testapp)"
assert_contains "$out_direct" "50.50.50.0         24   NA                 NA" "CLI direct route entry"

# 4. Adding the same direct route twice is a no-op (no duplicate row).
out_dup="$(printf 'config node R0_re route 50.50.50.0 24 direct -\nconfig node R0_re route 50.50.50.0 24 direct -\nshow node R0_re route\nquit\n' | ./testapp)"
count=$(printf '%s\n' "$out_dup" | grep -c '50.50.50.0')
[ "$count" -le 1 ] || fail "duplicate static route inserted: $count rows"

pass
