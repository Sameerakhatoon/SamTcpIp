#!/usr/bin/env bash
# Chapter 44: the send buffer and the retransmission timer.
#
# The simulator's wire never loses a frame, so `run node X drop-tcp
# <skip> <count>` (comm.c) drops TCP segments X sends. Verify:
#   - a lost data segment is sent again when the RTO (1 s, RFC 6298's
#     initial value) expires, from the send buffer, and arrives
#   - the RTO is a loss event (ch40): cwnd back to one MSS
#   - a lost SYN is sent again by the same timer and the handshake
#     completes
.  "$(dirname "$0")/lib.sh"

out="$(printf '%s\n' \
    'config node R1_re tcp-listen 80' \
    'run node R0_re ping 20.1.1.2' \
    'run node R0_re tcp-syn 20.1.1.2 80' \
    'run node R0_re drop-tcp 0 1' \
    'run node R0_re tcp-send 20.1.1.2 80 lost-once' \
    'run sleep 1500' \
    'show tcp-stats' \
    'quit' | ./testapp 2>&1)"

assert_contains "$out" "Test loss : R0_re : TCP segment dropped on eth0/0" "the data segment is dropped"
assert_contains "$out" "TCP timer : R0_re : RTO state=ESTABLISHED snd_una=8193 snd_nxt=8202 try 1" "RTO fires"
assert_contains "$out" "TCP cwnd : R0_re : LOSS flight=9 cwnd=1460 ssthresh=2920" "RTO is a loss event"
assert_contains "$out" "TCP recv : R1_re : data seq=8193 len=9 \`lost-once\`" "the retransmission arrives"
assert_contains "$out" "TCP stats : rto=1" "one RTO counted"

syn="$(printf '%s\n' \
    'config node R1_re tcp-listen 80' \
    'run node R0_re ping 20.1.1.2' \
    'run node R0_re drop-tcp 0 1' \
    'run node R0_re tcp-syn 20.1.1.2 80' \
    'run sleep 1500' \
    'show node R0_re tcp' \
    'quit' | ./testapp 2>&1)"

assert_contains "$syn" "TCP timer : R0_re : RTO state=SYN_SENT" "SYN timer fires"
n_syn=$(printf '%s\n' "$syn" | grep -c 'TCP send : R0_re : SYN seq=8192 to 20.1.1.2:80' || true)
assert_eq 2 "$n_syn" "the SYN goes twice"
assert_contains "$syn" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED" "handshake completes"

pass
