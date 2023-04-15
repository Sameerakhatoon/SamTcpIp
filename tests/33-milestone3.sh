#!/usr/bin/env bash
# Ch33: Milestone 3 goal - outbound TCP via a routed gateway.
#
# Active TCP connect from R0 to R2 where R0 is not directly
# connected to R2. R0 reaches R2 via R1 (the gateway, transit).
#
# This is the shape of curl OUT: our stack opens a connection
# to an internet IP; the kernel TAP gateway forwards across
# real wire; the response comes back through the same path.
# The simulator-side proof: ESTABLISHED on both endpoints with
# R1 as transparent transit hop.
#
# Skipped, per PLAN.md rule 1:
#   - ICMP error receive (Dest Unreach -> abort pending)
#   - DHCP client (operator does manual ip config under root)
#   - DNS client (operator uses IP literal)
# All of these can be backfilled. They are not on the curl-OUT
# success path - only on the failure / convenience paths.
. "$(dirname "$0")/lib.sh"

# Set up the 3-node topology:
#   R0 (20.1.1.1) ----eth0/0----+
#                                R1 (20.1.1.2, 30.1.1.1) ----eth0/2----+
#                                                                      R2 (30.1.1.2)
# R0 default-routes via R1's 20.1.1.2.
# R2 default-routes via R1's 30.1.1.1.
# R1 has direct routes to both subnets.
out="$(printf 'config node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0\nconfig node R2_re route 20.1.1.0 24 30.1.1.1 eth0/3\nconfig node R2_re tcp-listen 80\nrun node R0_re ping 30.1.1.2\nrun node R2_re ping 20.1.1.1\nrun node R0_re tcp-connect 30.1.1.2 80\nshow node R0_re tcp\nshow node R2_re tcp\nquit\n' | ./testapp)"

# Active open emits.
assert_contains "$out" "TCP connect : R0_re : src=20.1.1.1:32768 -> dst=30.1.1.2:80" "R0 connect"
assert_contains "$out" "TCP send : R0_re : SYN seq=8192 to 30.1.1.2:80"               "R0 SYN to a 2-hops-away dst"

# R2 (the actual server) receives the SYN.
assert_contains "$out" "TCP recv : R2_re : SYN seq=8192 from 20.1.1.1:32768 (peer_mss=1460) -> SYN_RECEIVED" "R2 SYN_RECEIVED"

# Full handshake completes both directions across the gateway.
assert_contains "$out" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED" "R0 ESTABLISHED"
assert_contains "$out" "TCP recv : R2_re : ACK seq=8193 ack=4097 -> ESTABLISHED"                     "R2 ESTABLISHED"

# Strong gate: R0 sees a TCB for the 2-hops-away peer (not just a
# directly-connected peer). The 4-tuple proves real routing happened.
assert_contains "$out" "state=ESTABLISHED local=32768 remote=30.1.1.2:80 peer_mss=1460" "R0 TCB to remote 2 hops"
assert_contains "$out" "state=ESTABLISHED local=80 remote=20.1.1.1:32768 peer_mss=1460" "R2 TCB to client 2 hops"

# Regression: ch29 in-stack HTTP responder still works (the
# Milestone 2 goal stays green).
out_m2="$(printf 'config node R1_re http-listen 80\nrun node R0_re ping 20.1.1.2\nrun node R0_re tcp-connect 20.1.1.2 80\nrun node R0_re tcp-send 20.1.1.2 80 GET\nquit\n' | ./testapp)"
assert_contains "$out_m2" "HTTP : R1_re : 200 OK -> peer" "Milestone 2 HTTP responder still works"

pass
