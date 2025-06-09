#!/usr/bin/env bash
# Ch26: TCP orderly close (FIN states).
#
# Adds the post-ESTABLISHED FSM transitions: FIN_WAIT_1,
# FIN_WAIT_2, CLOSE_WAIT, LAST_ACK. TIME_WAIT collapsed to CLOSED
# (no 2*MSL timer in this scope; documented). Chapter 44
# brings TIME_WAIT back: see tests/49-tcp-time-wait.sh.
#
# ch24 (retransmit) and ch25 (send-queue) skipped by the scope rule
# - they are wire-quality polish for lossy networks; curl on a
# localhost TAP wire does not need them for the MVP. The plan
# acknowledges this jump and a later chapter can backfill. (Chapter 44
# did: tests/44-tcp-retransmit.sh, 48-tcp-recovery.sh.)
#
# Test plan: full request-response-close cycle.
#   1. Handshake.
#   2. Client GET payload, server cumulative ACK.
#   3. Client closes -> FIN_WAIT_1 -> FIN_WAIT_2 (server acks).
#   4. Server closes -> LAST_ACK -> CLOSED.
#   5. Client receives FIN+ACK and lands in TIME_WAIT (was CLOSED).
. "$(dirname "$0")/lib.sh"

out="$(printf 'config node R1_re tcp-listen 80\nrun node R0_re ping 20.1.1.2\nrun node R0_re tcp-syn 20.1.1.2 80\nrun node R0_re tcp-send 20.1.1.2 80 GET\nrun node R0_re tcp-close 20.1.1.2 80\nrun node R1_re tcp-close 20.1.1.1 33333\nshow node R0_re tcp\nshow node R1_re tcp\nquit\n' | ./testapp)"

# Handshake regression (ch22).
assert_contains "$out" "TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED" "ch22 handshake"

# Data regression (ch23).
assert_contains "$out" "TCP recv : R1_re : data seq=8193 len=3 \`GET\`"                              "ch23 data"
assert_contains "$out" "TCP send : R1_re : ACK seq=4097 ack=8196"                                     "ch23 cumulative ACK"

# Active close (R0 initiates).
assert_contains "$out" "TCP close : R0_re : ESTABLISHED -> FIN_WAIT_1"                               "R0 enters FIN_WAIT_1"
assert_contains "$out" "TCP send : R0_re : FIN seq=8196 ack=4097 to 20.1.1.2:80"                     "R0 sends FIN"
assert_contains "$out" "TCP recv : R1_re : FIN seq=8196 -> CLOSE_WAIT"                               "R1 enters CLOSE_WAIT"
assert_contains "$out" "TCP recv : R0_re : ACK ack=8197 -> FIN_WAIT_2"                               "R0 enters FIN_WAIT_2"

# Passive close (R1 finishes the dance).
assert_contains "$out" "TCP close : R1_re : CLOSE_WAIT -> LAST_ACK"                                  "R1 enters LAST_ACK"
assert_contains "$out" "TCP send : R1_re : FIN seq=4097 ack=8197 to 20.1.1.1:33333"                  "R1 sends FIN"
# Chapter 44: the side that closed first waits in
# TIME_WAIT (2 s here) instead of going straight to CLOSED; test 49
# watches it end.
assert_contains "$out" "TCP recv : R0_re : FIN seq=4097 -> TIME_WAIT"                                "R0 lands in TIME_WAIT"
assert_contains "$out" "TCP recv : R1_re : ACK ack=4098 -> CLOSED"                                   "R1 lands in CLOSED"

# Both TCBs show CLOSED in the dump.
assert_contains "$out" "state=TIME_WAIT local=33333 remote=20.1.1.2:80"                              "R0 TCB dump shows TIME_WAIT"
assert_contains "$out" "state=CLOSED local=80 remote=20.1.1.1:33333"                                 "R1 TCB dump shows CLOSED"

# Regression.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2" "ping regression"

pass
