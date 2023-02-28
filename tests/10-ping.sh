#!/usr/bin/env bash
# Ch10: ping app on top of the L4 protocol-handler registry.
# Validates the round-trip:
#   R0_re sends PingMsg(REQ, seq) to R1_re's 20.1.1.2
#   R1_re receives via the registered PING_PROTO handler
#   R1_re echoes a REPLY back, src/dst swapped
#   R0_re's same handler logs "Ping reply : R0_re : seq=N from ..."
#
# `run node ping` fires 3 requests with sleeps between so:
#   seq 1: ARP-misses outbound, seeds R0->R1 cache
#   seq 2: reaches R1, R1 ARP-misses on reply path, seeds R1->R0
#   seq 3: full round-trip, reply lands
. "$(dirname "$0")/lib.sh"

out="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"

# Outbound REQ recv on R1.
assert_contains "$out" "Ping recv : R1_re : REQ seq=" "R1_re receives the REQ"
# At least one reply lands back on R0.
assert_contains "$out" "Ping reply : R0_re : seq=3 from 20.1.1.2" "seq 3 round-trip succeeds"
# ARP-miss diagnostic on the first attempt (handler IS called -
# the IP-layer ARP request fires, packet drops).
assert_contains "$out" "ARP miss for 20.1.1.2" "first attempt ARP miss reported"
# The ping handler explicitly chose IF_IP as src (not loopback) so
# the reply could route back via R1's direct route.
assert_contains "$out" "REQ seq=2 from 20.1.1.1" "src_ip is R0's eth0/0 (not loopback)"

# Negative: an IP nobody routes to drops with "no route".
out_noroute="$(printf 'run node R0_re ping 99.99.99.99\nquit\n' | ./testapp)"
assert_contains "$out_noroute" "no route" "drop with diagnostic when no route"

pass
