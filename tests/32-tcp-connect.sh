#!/usr/bin/env bash
# Ch32: ephemeral port allocation + tcp_connect.
#
# tcp_send_syn from ch22 used a fixed src_port (33333) for test
# determinism. Real outbound TCP needs unique source ports per
# connection so the 4-tuple is unique.
#
# tcp_alloc_ephemeral_port walks existing TCBs in the Linux
# ephemeral range 32768-60999, returning the first free port for
# the (local_ip, remote_ip, remote_port) tuple.
#
# tcp_connect(node, dst_ip, dst_port) = pick_src_ip + alloc_port +
# send_syn. The headline public API for active opens.
#
# CLI: run node X tcp-connect <ip> <dport>.
#
# Test plan:
#   1. Two back-to-back tcp-connects to the same dst get distinct
#      local ports.
#   2. Each connect produces a full handshake -> ESTABLISHED.
.  "$(dirname "$0")/lib.sh"

out="$(printf 'config node R1_re tcp-listen 80\nrun node R0_re ping 20.1.1.2\nrun node R0_re tcp-connect 20.1.1.2 80\nrun node R0_re tcp-connect 20.1.1.2 80\nshow node R0_re tcp\nquit\n' | ./testapp)"

# First connect picks 32768 (start of the pool).
assert_contains "$out" "TCP connect : R0_re : src=20.1.1.1:32768 -> dst=20.1.1.2:80" "first connect uses 32768"

# Second connect picks 32769 (next free).
assert_contains "$out" "TCP connect : R0_re : src=20.1.1.1:32769 -> dst=20.1.1.2:80" "second connect uses 32769"

# Both handshakes complete. Chapter 44: each connection
# has its own ISS, 64 Ki apart, so the second is 0x12000 both ways.
assert_contains "$out" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED" "first handshake"
assert_contains "$out" "TCP recv : R0_re : SYN-ACK seq=69632 ack=73729 (peer_mss=1460) -> ESTABLISHED" "second handshake, fresh ISS"
n_estab=$(printf '%s\n' "$out" | grep -c '^TCP recv : R0_re : SYN-ACK seq=.* -> ESTABLISHED' || true)
if [ "$n_estab" -lt 2 ]; then
    fail "expected 2 ESTABLISHED transitions on R0; got $n_estab"
fi

# show tcp on R0 shows two distinct ESTABLISHED TCBs.
assert_contains "$out" "state=ESTABLISHED local=32768 remote=20.1.1.2:80" "TCB 32768 listed"
assert_contains "$out" "state=ESTABLISHED local=32769 remote=20.1.1.2:80" "TCB 32769 listed"

# Regression: ch22 fixed-port tcp-syn still works for tests that
# care about a specific 4-tuple.
out_legacy="$(printf 'config node R1_re tcp-listen 81\nrun node R0_re ping 20.1.1.2\nrun node R0_re tcp-syn 20.1.1.2 81\nquit\n' | ./testapp)"
assert_contains "$out_legacy" "TCP send : R0_re : SYN seq=8192 to 20.1.1.2:81" "ch22 fixed-port still works"

pass
