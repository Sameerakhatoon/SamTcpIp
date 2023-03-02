#!/usr/bin/env bash
# Ch1: testapp builds the 3-node ring and dump_graph prints all three
# Nodes with their wired interfaces and the link cost.
. "$(dirname "$0")/lib.sh"

# ch3 moved the dump behind a CLI command; pass `show topology` so
# ch1's invariants (Nodes, links, costs) still get checked.
out="$(./testapp --cmd 'show topology')"
assert_contains "$out" "Topology Name = Hello World Generic Graph" "topology header"
assert_contains "$out" "Node Name = R0_re"  "R0 dumped"
assert_contains "$out" "Node Name = R1_re"  "R1 dumped"
assert_contains "$out" "Node Name = R2_re"  "R2 dumped"
assert_contains "$out" "Interface Name : eth0/0, Nbr Node R1_re, cost = 1" "R0->R1 link"
assert_contains "$out" "Interface Name : eth0/4, Nbr Node R2_re, cost = 1" "R0->R2 link"
assert_contains "$out" "Interface Name : eth0/2, Nbr Node R2_re, cost = 1" "R1->R2 link"
pass
