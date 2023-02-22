#!/usr/bin/env bash
# Ch2: dump_nw_graph adds device flags, loopback, per-intf IP/mask,
# and a deterministic MAC string. Confirm the topology header, all
# three loopbacks, and a couple of IP/MAC lines land in the output.
. "$(dirname "$0")/lib.sh"

# ch3 moved the dump behind a CLI command.
out="$(./testapp --cmd 'show topology')"
assert_contains "$out" "Topology Name = Hello World Generic Graph" "topology header"
assert_contains "$out" "node flags : 1"        "L3_ROUTER flag (=1) set"
assert_contains "$out" "lo addr : 122.1.1.0/32" "R0 loopback"
assert_contains "$out" "lo addr : 122.1.1.1/32" "R1 loopback"
assert_contains "$out" "lo addr : 122.1.1.2/32" "R2 loopback"
assert_contains "$out" "IP Addr = 20.1.1.1/24" "R0 eth0/0 IP"
assert_contains "$out" "IP Addr = 40.1.1.1/24" "R0 eth0/4 IP"
assert_contains "$out" "IP Addr = 20.1.1.2/24" "R1 eth0/1 IP"
assert_contains "$out" "IP Addr = 30.1.1.1/24" "R1 eth0/2 IP"
assert_contains "$out" "IP Addr = 30.1.1.2/24" "R2 eth0/3 IP"
assert_contains "$out" "IP Addr = 40.1.1.2/24" "R2 eth0/5 IP"
# MAC heuristic concatenates node_name + if_name, so first byte of
# the MAC line for any R0_re intf is the ASCII code of 'R' (82).
assert_contains "$out" "MAC : 82:"             "MAC byte 0 is 'R' (82)"
pass
