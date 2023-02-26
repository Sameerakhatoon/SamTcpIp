#!/usr/bin/env bash
# Ch7: VLAN isolation through a VLAN-aware L2 switch.
# Topology:
#   H1 (10.1.1.1/24)  <- vlan 10 ->  +-------+  <- vlan 10 -> H2 (10.1.1.2/24)
#                                    | L2SW  |
#                                    +-------+
#                                       |
#                                    <- vlan 20 ->
#                                    H3 (10.1.1.3/24)
#
# Same-VLAN ARP succeeds (H1 -> H2). Cross-VLAN ARP is blocked:
# the broadcast tagged vlan10 reaches H2 only (port eth0/7 is in
# vlan 10), never H3 (eth0/9 is in vlan 20).
. "$(dirname "$0")/lib.sh"

# Case 1: same-vlan ARP.
out_same="$(printf 'run node H1 resolve-arp 10.1.1.2\nshow node H1 arp\nquit\n' | ./testapp --topo vlan)"
assert_contains "$out_same" "ARP Broadcast msg recvd on interface eth0/6 of node H2" "vlan10 broadcast reached H2"
assert_contains "$out_same" "ARP reply msg recvd on interface eth0/4 of node H1"    "H2 replied to H1"
assert_contains "$out_same" "IP : 10.1.1.2"                                          "H1's ARP cache holds 10.1.1.2"

# Cross-vlan ARP for H3 from H1.
out_cross="$(printf 'run node H1 resolve-arp 10.1.1.3\nshow node H1 arp\nquit\n' | ./testapp --topo vlan)"
# Negative assertion: H3 must NOT see the broadcast.
case "$out_cross" in
    *"of node H3"*)
        fail "H3 should not see a vlan10 broadcast; got: $out_cross"
        ;;
esac
# No reply: nothing should hit H1's eth0/4 from H3's side.
case "$out_cross" in
    *"ARP reply msg recvd on interface eth0/4 of node H1"*)
        fail "unexpected ARP reply on H1 from cross-vlan resolve: $out_cross"
        ;;
esac
# H2 did get the broadcast and drops it on dst-IP mismatch.
assert_contains "$out_cross" "ARP Broadcast msg recvd on interface eth0/6 of node H2" "vlan10 flood still reaches H2"
assert_contains "$out_cross" "ARP Broadcast req msg dropped"                          "H2 drops mismatched target IP"

pass
