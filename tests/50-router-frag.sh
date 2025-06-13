#!/usr/bin/env bash
# Chapter 44: ICMP errors from a router, fragmenting
# on forward, reassembly past 1600 bytes.
#
# R0_re -- R1_re -- R2_re. The R0_re/R1_re link is raised to MTU 1500;
# R1_re/R2_re keeps the simulator's 120. Verify:
#   - a 1000-byte ping leaves R0_re whole and R1_re splits it to fit
#     120 (RFC 791: payloads a multiple of 8, MF on all but the last);
#     R2_re reassembles, the reply comes back with its data intact
#   - the same ping with DF is dropped at R1_re, which sends
#     Destination Unreachable, Fragmentation Needed, with next-hop
#     MTU 120 (RFC 1191); R0_re puts 120 in its path MTU cache
#   - a 4000-byte ping (more than ch34's 1600-byte reassembly buffer)
#     goes and comes back whole
#   - a datagram R1_re has no route for gets Destination Unreachable,
#     net (code 0) instead of a silent drop
.  "$(dirname "$0")/lib.sh"

out="$(printf '%s\n' \
    'config node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0' \
    'config node R0_re route 99.0.0.0 8 20.1.1.2 eth0/0' \
    'config node R2_re route 20.1.1.0 24 30.1.1.1 eth0/3' \
    'config node R0_re interface eth0/0 mtu 1500' \
    'config node R1_re interface eth0/1 mtu 1500' \
    'run node R0_re ping 30.1.1.2' \
    'run node R0_re ping-size 30.1.1.2 1000' \
    'run node R0_re ping-df 30.1.1.2 1000' \
    'run pmtu show' \
    'run node R0_re ping-size 30.1.1.2 4000' \
    'run node R0_re ping-ttl 99.1.2.3 64' \
    'show node R1_re l3-stats' \
    'quit' | ./testapp 2>&1)"

assert_contains "$out" "IP frag fwd : R1_re : id=7 off=0 len=96 MF=1" "R1_re fragments on forward"
assert_contains "$out" "IP frag fwd : R1_re : id=7 off=960 len=48 MF=0" "last piece"
assert_contains "$out" "IP frag done : R2_re : id=7 total=1008 bytes" "R2_re reassembles"
assert_contains "$out" "Ping answer : seq=1 from 30.1.1.2 type=0 code=0 ttl=63 bytes=1000 data=ok" "1000-byte reply intact"
assert_contains "$out" "L3 drop : R1_re : 1028 bytes with DF, MTU 120" "DF datagram dropped"
assert_contains "$out" "Ping recv : R0_re : Frag-Needed for 30.1.1.2 (next-hop MTU 120)" "Fragmentation Needed"
assert_contains "$out" "30.1.1.2           mtu=120" "path MTU cached"
assert_contains "$out" "Ping answer : seq=1 from 30.1.1.2 type=0 code=0 ttl=63 bytes=4000 data=ok" "4000-byte reply intact"
assert_contains "$out" "Ping recv : R0_re : Destination Unreachable code 0 for 99.1.2.3 from 20.1.1.2" "net unreachable"
assert_contains "$out" "L3 stats : R1_re : unreach_sent=1 fragmented=1 frag_needed=1" "router counters"

pass
