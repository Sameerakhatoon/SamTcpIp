#!/usr/bin/env bash
# Chapter 44: a listener and its children.
#
# Closing a listener resets its half-open children. R0_re's
# third leg is dropped (drop-tcp 1 1: the SYN passes, the ACK is lost),
# so R1_re's child stays in SYN_RECEIVED. Closing the listener sends it
# a RST|ACK; R0_re, which thinks it is connected, goes to CLOSED.
#
# A full accept queue delays the handshake instead of closing
# it. Backlog 1 on R1_re:80, two connects from R0_re: the second third
# leg is ignored while the first connection holds the queue; when R1_re
# closes that one, the child's SYN-ACK goes again on its timer, R0_re
# (ESTABLISHED) answers the SYN with an ACK and the handshake finishes.
.  "$(dirname "$0")/lib.sh"

a="$(printf '%s\n' \
    'config node R1_re tcp-listen 80' \
    'run node R0_re ping 20.1.1.2' \
    'run node R0_re drop-tcp 1 1' \
    'run node R0_re tcp-syn 20.1.1.2 80' \
    'show node R1_re tcp' \
    'run node R1_re tcp-unlisten 80' \
    'quit' | ./testapp 2>&1)"

assert_contains "$a" "Test loss : R0_re : TCP segment dropped" "third leg lost"
assert_contains "$a" "state=SYN_RECEIVED local=80 remote=20.1.1.1:33333" "half-open child"
assert_contains "$a" "TCP close : R1_re : listener on port 80 closed" "listener closed"
assert_contains "$a" "TCP send : R1_re : RST|ACK seq=4097 ack=8193 to 20.1.1.1:33333" "child reset"
assert_contains "$a" "TCP recv : R0_re : RST received in state=ESTABLISHED -> CLOSED" "peer told"

b="$(printf '%s\n' \
    'config node R1_re tcp-listen 80' \
    'config node R1_re tcp-backlog 80 1' \
    'run node R0_re ping 20.1.1.2' \
    'run node R0_re tcp-connect 20.1.1.2 80' \
    'run node R0_re tcp-connect 20.1.1.2 80' \
    'show node R1_re tcp' \
    'run node R1_re tcp-close 20.1.1.1 32768' \
    'run sleep 3500' \
    'show node R1_re tcp' \
    'quit' | ./testapp 2>&1)"

assert_contains "$b" "TCP recv : R1_re : accept queue full, third leg from port 32769 ignored" "queue full"
assert_contains "$b" "state=SYN_RECEIVED local=80 remote=20.1.1.1:32769" "child waits in SYN_RECEIVED"
assert_contains "$b" "TCP timer : R1_re : RTO state=SYN_RECEIVED" "SYN-ACK timer"
assert_contains "$b" "TCP recv : R0_re : SYN seq=69632 in state=ESTABLISHED -> ACK" "client ACKs the SYN again"
assert_contains "$b" "TCP recv : R1_re : ACK seq=73729 ack=69633 -> ESTABLISHED" "handshake finished"
assert_contains "$b" "state=ESTABLISHED local=80 remote=20.1.1.1:32769" "second connection established"

pass
