#!/usr/bin/env bash
# Ch10: ping app on top of the L4 protocol-handler registry.
#
# ch11 rewrote the wire format from a homegrown PING_PROTO=201 +
# PingMsg to real RFC 792 ICMP. The behavior under test stays the
# same (the request/reply round-trip) but the log strings now say
# "ICMP echo request" / "Ping reply" instead of "REQ" / "REPLY".
#
# Validates the round-trip:
#   R0_re sends ECHO REQUEST to R1_re's 20.1.1.2
#   R1_re receives via the registered ICMP handler (proto 1)
#   R1_re echoes a REPLY back, type flipped + checksum recomputed
#   R0_re's same handler logs "Ping reply : R0_re : seq=N from ..."
. "$(dirname "$0")/lib.sh"

out="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"

# Outbound REQ recv on R1.
assert_contains "$out" "Ping recv : R1_re : ICMP echo request seq=" "R1_re receives the echo request"
# At least one reply lands back on R0.
assert_contains "$out" "Ping reply : R0_re : seq=3 from 20.1.1.2" "seq 3 round-trip succeeds"
# ARP-miss diagnostic on the first attempt.
assert_contains "$out" "ARP miss for 20.1.1.2" "first attempt ARP miss reported"
# Source seen on R1 is R0's eth0/0 IP (the L3 originate path picks
# the OIF's IP as src when emitting through the route).
assert_contains "$out" "ICMP echo request seq=2 from 20.1.1.1" "src_ip is R0's eth0/0"

# Negative: an IP nobody routes to drops with "no route".
out_noroute="$(printf 'run node R0_re ping 99.99.99.99\nquit\n' | ./testapp)"
assert_contains "$out_noroute" "no route" "drop with diagnostic when no route"

pass
