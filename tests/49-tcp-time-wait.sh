#!/usr/bin/env bash
# Chapter 44: TIME_WAIT.
#
# RFC 793: the side that closes first waits 2 MSL in TIME_WAIT, so a
# lost final ACK can be sent again and old segments die out. ch26 went
# from FIN_WAIT_2 straight to CLOSED.
#
#  A. R1_re closes first. Its ACK of R0_re's FIN is dropped
#     (drop-tcp 1 1: the FIN passes, the ACK is lost), so R0_re, in
#     LAST_ACK, sends its FIN again on the RTO; R1_re in TIME_WAIT
#     ACKs it again and R0_re closes. A new SYN on the same 4-tuple
#     with a higher sequence number ends the TIME_WAIT early
#     (RFC 1122 4.2.2.13) and opens a new connection.
#  B. With run tcp-time-wait 300 the TIME_WAIT ends after 300 ms.
.  "$(dirname "$0")/lib.sh"

a="$(printf '%s\n' \
    'config node R1_re tcp-listen 80' \
    'run node R0_re ping 20.1.1.2' \
    'run node R0_re tcp-syn 20.1.1.2 80' \
    'run node R1_re drop-tcp 1 1' \
    'run node R1_re tcp-close 20.1.1.1 33333' \
    'run node R0_re tcp-close 20.1.1.2 80' \
    'run sleep 600' \
    'show node R1_re tcp' \
    'run node R0_re tcp-syn 20.1.1.2 80' \
    'show node R1_re tcp' \
    'quit' | ./testapp 2>&1)"

assert_contains "$a" "TCP recv : R1_re : FIN seq=8193 -> TIME_WAIT" "R1_re in TIME_WAIT"
assert_contains "$a" "Test loss : R1_re : TCP segment dropped" "final ACK lost"
assert_contains "$a" "TCP timer : R0_re : RTO state=LAST_ACK" "R0_re sends its FIN again"
assert_contains "$a" "TCP recv : R1_re : old data seq=8193 rcv_nxt=8194 (ACK again)" "TIME_WAIT ACKs it again"
assert_contains "$a" "TCP recv : R0_re : ACK ack=8194 -> CLOSED" "R0_re closes"
assert_contains "$a" "state=TIME_WAIT local=80 remote=20.1.1.1:33333" "still in TIME_WAIT"
assert_contains "$a" "TCP recv : R1_re : SYN seq=73728 ends TIME_WAIT" "new SYN ends TIME_WAIT"
assert_contains "$a" "TCP recv : R1_re : SYN seq=73728 from 20.1.1.1:33333 (peer_mss=1460) -> SYN_RECEIVED" "new connection"

b="$(printf '%s\n' \
    'run tcp-time-wait 300' \
    'config node R1_re tcp-listen 80' \
    'run node R0_re ping 20.1.1.2' \
    'run node R0_re tcp-syn 20.1.1.2 80' \
    'run node R0_re tcp-close 20.1.1.2 80' \
    'run node R1_re tcp-close 20.1.1.1 33333' \
    'show node R0_re tcp' \
    'run sleep 500' \
    'show node R0_re tcp' \
    'quit' | ./testapp 2>&1)"

assert_contains "$b" "TCP time-wait : 300 ms" "TIME_WAIT length set"
assert_contains "$b" "TCP recv : R0_re : FIN seq=4097 -> TIME_WAIT" "R0_re in TIME_WAIT"
assert_contains "$b" "state=TIME_WAIT local=33333 remote=20.1.1.2:80" "TIME_WAIT before"
assert_contains "$b" "state=CLOSED local=33333 remote=20.1.1.2:80" "CLOSED after 300 ms"

pass
