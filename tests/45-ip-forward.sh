#!/usr/bin/env bash
# Chapter 44: the forwarding switch, its counters, Time
# Exceeded and the TTL of an originated datagram.
#
# R0_re pings R2_re's 30.1.1.2 through R1_re. Verify:
#   - forwarded replies arrive with TTL 63 (64, less one at R1_re)
#   - a ping with TTL 1 dies at R1_re, which sends RFC 792 Time
#     Exceeded (type 11 code 0) quoting the request, so R0_re learns
#     which echo request it was about
#   - with ip-forward off R1_re drops the transit datagram and counts it
.  "$(dirname "$0")/lib.sh"

out="$(printf '%s\n' \
    'config node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0' \
    'config node R2_re route 20.1.1.0 24 30.1.1.1 eth0/3' \
    'run node R0_re ping 30.1.1.2' \
    'run node R0_re ping-ttl 30.1.1.2 1' \
    'show node R1_re l3-stats' \
    'config node R1_re ip-forward off' \
    'run node R0_re ping-ttl 30.1.1.2 64' \
    'show node R1_re l3-stats' \
    'quit' | ./testapp 2>&1)"

assert_contains "$out" "Ping reply : R0_re : seq=3 from 30.1.1.2 ttl=63" "forwarded reply, TTL 63"
assert_contains "$out" "L3 drop : R1_re : TTL expired" "TTL 1 dies at the router"
assert_contains "$out" "Ping recv : R0_re : Time Exceeded seq=1 from 20.1.1.2" "Time Exceeded names the request"
assert_contains "$out" "L3 stats : R1_re : forward=on forwarded=6 ttl_expired=1 refused=0 no_route=0" "counters, forwarding on"
assert_contains "$out" "L3 drop : R1_re : not for us and forwarding is off" "forwarding off drops"
assert_contains "$out" "L3 stats : R1_re : forward=off forwarded=6 ttl_expired=1 refused=1 no_route=0" "counters, forwarding off"

pass
