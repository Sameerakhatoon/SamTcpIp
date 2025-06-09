#!/usr/bin/env bash
# Chapter 44: RTT estimate, fast
# retransmit, the out-of-order queue, and an ACK past a rewound snd_nxt.
#
# Both sides advertise 65535 (run tcp-rwnd). Four 100-byte sends grow
# cwnd in slow start; then the first segment of a burst is dropped
# (drop-tcp 0 1).
#
#  A. Burst of 4 x 1000: R1_re keeps segments 2..4 (out of order) and
#     answers each with a duplicate ACK; the third makes R0_re resend
#     at snd_una at once (RFC 5681 fast retransmit), long before the
#     200 ms RTO. The resend (one MSS, 1460 bytes) fills the hole;
#     R1_re hands over what it kept and ACKs all 4000 bytes, which
#     ends NewReno recovery (RFC 6582).
#  B. Burst of 2 x 1000: one duplicate ACK is not enough, so the RTO
#     fires and goes back to snd_una (snd_nxt rewound). R1_re, which
#     kept segment 2, ACKs 2000 bytes, past the rewound snd_nxt: the sender
#     takes an ACK up to snd_max, so it is not thrown away.
#  RTT: each ACK of new data gives an RFC 6298 sample; the RTO is the
#     estimate (clamped to 200 ms), not the initial 1 s.
.  "$(dirname "$0")/lib.sh"

warmup='run tcp-rwnd 65535
config node R1_re tcp-listen 80
run node R0_re ping 20.1.1.2
run node R0_re tcp-syn 20.1.1.2 80
run node R0_re tcp-send-burst 20.1.1.2 80 4 100
run node R0_re drop-tcp 0 1'

a="$(printf '%s\n' "$warmup" \
    'run node R0_re tcp-send-burst 20.1.1.2 80 4 1000' \
    'show node R0_re tcp' \
    'show tcp-stats' \
    'quit' | ./testapp 2>&1)"

assert_contains "$a" "TCP recv : R1_re : out-of-order data seq=9593 rcv_nxt=8593 (kept)" "segment 2 kept"
assert_contains "$a" "TCP recv : R1_re : out-of-order data seq=11593 rcv_nxt=8593 (kept)" "segment 4 kept"
assert_contains "$a" "TCP fast : R0_re : 3 duplicate ACKs, resend seq=8593 flight=4000 ssthresh=2920" "fast retransmit"
assert_contains "$a" "TCP send : R0_re : data seq=8593 len=1460" "one MSS from snd_una"
assert_contains "$a" "TCP recv : R1_re : out-of-order data seq=10053 len=540 now in order" "the queue drains"
assert_contains "$a" "TCP send : R1_re : ACK seq=4097 ack=12593" "all 4000 bytes ACKed"
assert_contains "$a" "TCP fast : R0_re : recovery done ack=12593 cwnd=2920" "NewReno recovery ends"
assert_contains "$a" "TCP stats : rto=0 fast_rtx=1 ooo_kept=3" "no RTO, one fast retransmit"
printf '%s\n' "$a" | grep -Eq "TCP rtt : R0_re : sample [0-9]+ ms srtt=[0-9]+ rttvar=[0-9]+ rto=[0-9]+" \
    || fail "no RTT sample"
printf '%s\n' "$a" | grep -Eq "state=ESTABLISHED local=33333 .* srtt=[0-9]+ rto=(2[0-9][0-9]|[3-9][0-9][0-9])$" \
    || fail "RTO is not the estimate (200..999 ms)"

b="$(printf '%s\n' "$warmup" \
    'run node R0_re tcp-send-burst 20.1.1.2 80 2 1000' \
    'run sleep 500' \
    'show tcp-stats' \
    'quit' | ./testapp 2>&1)"

assert_contains "$b" "TCP recv : R1_re : out-of-order data seq=9593 rcv_nxt=8593 (kept)" "segment 2 kept"
assert_contains "$b" "TCP timer : R0_re : RTO state=ESTABLISHED snd_una=8593 snd_nxt=10593 try 1" "RTO fires"
assert_contains "$b" "TCP send : R0_re : data seq=8593 len=1460" "go back to snd_una"
assert_contains "$b" "TCP send : R1_re : ACK seq=4097 ack=10593" "ACK past the rewound snd_nxt"
assert_contains "$b" "TCP cwnd : R0_re : slow-start ack=10593 acked=2000" "taken up to snd_max"
assert_contains "$b" "TCP stats : rto=1 fast_rtx=0 ooo_kept=1" "one RTO"

pass
