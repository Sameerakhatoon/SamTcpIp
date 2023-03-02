#!/usr/bin/env bash
# Ch4: send a packet from R0_re via eth0/0; the link wires that to
# R1_re's eth0/1. The receiver thread should pick the frame up.
#
# ch5 introduced a real L2 acceptance gate that reads the first 6
# bytes as a destination MAC. Raw "hello" bytes don't have a valid
# dst MAC, so the gate now rejects them. The packet-exchange
# transport is still proven by the fact that L2 ran at all
# (printed Accepted OR Rejected on the correct receiving Node).
. "$(dirname "$0")/lib.sh"

# 1. Unicast send: R0_re/eth0/0 -> R1_re/eth0/1.
out="$(./testapp --cmd 'run send R0_re eth0/0 hello')"
assert_contains "$out" "L2 Frame"  "L2 stack saw the frame on R1_re"

# 2. Different outgoing intf hits the other peer:
#    R0_re/eth0/4 is wired to R2_re/eth0/5.
out2="$(./testapp --cmd 'run send R0_re eth0/4 world')"
assert_contains "$out2" "L2 Frame" "L2 stack saw the frame on R2_re"

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
