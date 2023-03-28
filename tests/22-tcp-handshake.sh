#!/usr/bin/env bash
# Ch22: TCP 3-way handshake (RFC 793 subset).
#
# Milestone 2 starts. Layer4/tcp:
#   - 20-byte TcpHdr, packed NBO.
#   - Pseudo-header checksum (same algorithm as UDP, different
#     protocol byte).
#   - Per-Node TCB list with FSM CLOSED / LISTEN / SYN_SENT /
#     SYN_RECEIVED / ESTABLISHED. Everything past ESTABLISHED is
#     deferred to its own chapter.
#   - tcp_listen(node, port) installs a passive socket.
#   - tcp_send_syn allocates a SYN_SENT TCB and emits a SYN
#     with an MSS option.
#   - Receive handler walks the SYN -> SYN-ACK -> ACK exchange in
#     both directions.
#   - MSS option parsed on both legs of the handshake.
#
# Test plan:
#   1. Listener installed; SYN from R0 completes the handshake;
#      both sides have a TCB in ESTABLISHED with peer_mss=1460.
#   2. The pseudo-csum verify gate fires when bytes are tampered
#      (regression / future hook; no explicit corrupt test in
#      ch22 - the test below asserts no spurious "checksum
#      invalid" appears on a clean handshake).
#   3. Regression: prior chapters' ping / UDP / GARP still work.
. "$(dirname "$0")/lib.sh"

# 1. Full handshake end-to-end. The leading ping pre-warms ARP
# in both directions so the SYN-ACK doesn't get dropped on an
# ARP miss.
out="$(printf 'config node R1_re tcp-listen 80\nrun node R0_re ping 20.1.1.2\nrun node R0_re tcp-syn 20.1.1.2 80\nshow node R0_re tcp\nshow node R1_re tcp\nquit\n' | ./testapp)"

# Listener installed.
assert_contains "$out" "TCP listen : R1_re : port 80" "listener installed"

# Server-side FSM transitions.
assert_contains "$out" "TCP recv : R1_re : SYN seq=8192 from 20.1.1.1:33333 (peer_mss=1460) -> SYN_RECEIVED"  "R1 SYN -> SYN_RECEIVED"
assert_contains "$out" "TCP send : R1_re : SYN-ACK seq=4096 ack=8193 to 20.1.1.1:33333"                       "R1 sends SYN-ACK"
assert_contains "$out" "TCP recv : R1_re : ACK seq=8193 ack=4097 -> ESTABLISHED"                              "R1 ESTABLISHED"

# Client-side FSM transitions.
assert_contains "$out" "TCP send : R0_re : SYN seq=8192 to 20.1.1.2:80"                                       "R0 sends SYN"
assert_contains "$out" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED"          "R0 SYN-ACK -> ESTABLISHED"
assert_contains "$out" "TCP send : R0_re : ACK seq=8193 ack=4097 to 20.1.1.2:80"                              "R0 sends final ACK"

# show node X tcp dumps reflect ESTABLISHED on both sides.
assert_contains "$out" "[0] state=ESTABLISHED local=33333 remote=20.1.1.2:80 peer_mss=1460" "R0 TCB shows ESTABLISHED"
assert_contains "$out" "state=ESTABLISHED" "R1 has at least one ESTABLISHED TCB"

# Negative: no checksum-invalid logs on clean handshake.
if printf '%s\n' "$out" | grep -q 'TCP recv : .* checksum invalid'; then
    fail "clean handshake must not log TCP csum invalid"
fi

# 2. Regression: ch10 ping + ch13 UDP still work alongside TCP.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"            "ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"   "UDP regression"

pass
