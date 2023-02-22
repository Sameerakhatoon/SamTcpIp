#!/usr/bin/env bash
# Ch4: send a packet from R0_re via eth0/0; the link wires that to
# R1_re's eth0/1, so the receiver thread should log a Layer 2 frame
# receipt on R1_re/eth0/1, followed immediately by a Layer 3
# promotion log (stub layer3_pkt_recv printf).
. "$(dirname "$0")/lib.sh"

# 1. Unicast send: R0_re/eth0/0 -> R1_re/eth0/1.
out="$(./testapp --cmd 'run send R0_re eth0/0 hello')"
assert_contains "$out" "Layer 2 Frame Recvd : Rcv Node R1_re, Intf : eth0/1" "L2 receipt on R1_re/eth0/1"
assert_contains "$out" "data recvd : hello"                                   "payload made it intact"
assert_contains "$out" "Layer 3 Packet Recvd : Rcv Node R1_re, Intf : eth0/1" "L3 promotion on R1_re/eth0/1"

# 2. Different outgoing intf hits the other peer:
#    R0_re/eth0/4 is wired to R2_re/eth0/5.
out2="$(./testapp --cmd 'run send R0_re eth0/4 world')"
assert_contains "$out2" "Layer 2 Frame Recvd : Rcv Node R2_re, Intf : eth0/5" "L2 receipt on R2_re/eth0/5"
assert_contains "$out2" "data recvd : world"                                   "second payload made it intact"

# 3. Bogus node / interface errors out cleanly without crashing.
if ./testapp --cmd 'run send NOPE eth0/0 x' >/tmp/_out 2>/tmp/_err; then
    fail "expected non-zero exit for unknown node"
fi
assert_contains "$(cat /tmp/_err)" "no such node" "rejects unknown node"

if ./testapp --cmd 'run send R0_re NOPE x' >/tmp/_out 2>/tmp/_err; then
    fail "expected non-zero exit for unknown interface"
fi
assert_contains "$(cat /tmp/_err)" "no such interface" "rejects unknown interface"
rm -f /tmp/_out /tmp/_err
pass
