#!/usr/bin/env bash
# Ch31: default route handling.
#
# The course's LPM (Layer3/layer3.c::l3rib_lookup_lpm) already
# special-cases 0.0.0.0/0 as a fallback - it walks the route
# list, tracks the longest specific match, and uses the default
# route ONLY if no specific match was found. ch31 verifies the
# contract with explicit tests and documents what the operator
# can rely on.
#
# Strong gate: with a default route installed, node_pick_src_ip
# for any non-routed dst returns the OIF's IP (not the loopback).
# That confirms LPM is finding the default + the ch30 helper is
# using it.
. "$(dirname "$0")/lib.sh"

# 1. Without default route: fallback to loopback.
out_no="$(printf 'show node R0_re pick-src 99.99.99.99\nquit\n' | ./testapp)"
assert_contains "$out_no" "pick-src : R0_re : dst=99.99.99.99 -> src=122.1.1.0" "no route -> loopback"

# 2. Install default route via 20.1.1.2 / eth0/0. Now pick-src
# for a non-connected dst returns the OIF's IP.
out_def="$(printf 'config node R0_re route 0.0.0.0 0 20.1.1.2 eth0/0\nshow node R0_re pick-src 99.99.99.99\nshow node R0_re route\nquit\n' | ./testapp)"
assert_contains "$out_def" "pick-src : R0_re : dst=99.99.99.99 -> src=20.1.1.1" "default route hits + OIF IP"
assert_contains "$out_def" "0.0.0.0            0    20.1.1.2           eth0/0"   "default route appears in routing table"

# 3. Specific route wins over default. Install a /24 for
# 30.1.1.0 via the OTHER gateway, then assert pick-src for
# 30.1.1.5 uses the specific route, not the default.
out_spec="$(printf 'config node R0_re route 0.0.0.0 0 40.1.1.2 eth0/4\nconfig node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0\nshow node R0_re pick-src 30.1.1.5\nshow node R0_re pick-src 99.99.99.99\nquit\n' | ./testapp)"
assert_contains "$out_spec" "pick-src : R0_re : dst=30.1.1.5 -> src=20.1.1.1"     "specific /24 wins"
assert_contains "$out_spec" "pick-src : R0_re : dst=99.99.99.99 -> src=40.1.1.1" "non-matching dst falls through to default"

# Regression.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2" "ping regression"

pass
