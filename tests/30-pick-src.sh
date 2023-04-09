#!/usr/bin/env bash
# Ch30: source IP via route lookup (shared helper).
#
# UDP (ch13) and TCP (ch22) each had inline near-identical
# pick_src_ip copies. ch30 promotes the algorithm to
# node_pick_src_ip in Layer3 and points both inlined helpers
# at it. Algorithm (in priority order):
#   1. LPM lookup. If a route exists with an explicit oif,
#      use that interface's IP.
#   2. Subnet-match on dst_ip for directly-connected.
#   3. Loopback fallback.
#   4. 0.
#
# Test plan:
#   1. Directly-connected dst -> subnet-match returns that
#      interface's IP.
#   2. Non-connected dst with no route -> loopback fallback.
#   3. Install a static route for the non-connected dst ->
#      the chosen src is the OIF's IP, not the loopback.
#   4. Regression: UDP + TCP + ping still work (they all use
#      the promoted helper now).
. "$(dirname "$0")/lib.sh"

out_a="$(printf 'show node R0_re pick-src 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_a" "pick-src : R0_re : dst=20.1.1.2 -> src=20.1.1.1" "subnet-match for directly-connected"

out_b="$(printf 'show node R0_re pick-src 30.1.1.2\nquit\n' | ./testapp)"
# Loopback for R0_re is 122.1.1.0 per topology.
assert_contains "$out_b" "pick-src : R0_re : dst=30.1.1.2 -> src=122.1.1.0" "loopback fallback when no route"

out_c="$(printf 'config node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0\nshow node R0_re pick-src 30.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_c" "pick-src : R0_re : dst=30.1.1.2 -> src=20.1.1.1" "LPM with explicit oif overrides loopback"

# Regression: TCP + UDP + ping still work via the promoted helper.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nconfig node R1_re tcp-listen 80\nrun node R0_re tcp-syn 20.1.1.2 80\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"            "ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"   "UDP regression"
assert_contains "$out_reg" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED" "TCP regression"

pass
