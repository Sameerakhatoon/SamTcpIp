#!/usr/bin/env bash
# Ch11: real ICMP (RFC 792 wire format + RFC 1071 checksum).
#
# ch10 shipped a homegrown PING_PROTO=201 + PingMsg struct on the
# L3 protocol-handler registry. ch11 replaces with the real thing:
#   - IcmpHdr (type, code, checksum, identifier, sequence)
#   - icmp_checksum (RFC 1071, returned in host order, stored as NBO)
#   - protocol number 1
#   - ECHO REQUEST = 8, ECHO REPLY = 0
#
# This test exercises two paths:
#
#   1. Happy round-trip - a valid ECHO REQUEST gets the wire-correct
#      checksum, R1 verifies + flips type to REPLY + recomputes csum
#      + sends back. R0 gets "Ping reply" log.
#
#   2. Corrupted checksum - one bit of the on-wire checksum is XORed
#      after compute. The receiver MUST drop with "ICMP checksum
#      invalid". No reply lands.
#
# The corrupted-csum branch is the strong gate: it asserts the
# RFC 1071 verify property (csum-over-whole-msg == 0) is enforced,
# not just nominally computed.
. "$(dirname "$0")/lib.sh"

# 1. Happy round-trip.
out_ok="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"

assert_contains "$out_ok" "Ping recv : R1_re : ICMP echo request seq="     "R1 receives a real ICMP echo request"
assert_contains "$out_ok" "Ping reply : R0_re : seq=3 from 20.1.1.2"       "R0 sees the reply land"

# Negative: no checksum-invalid drop on clean traffic.
if printf '%s\n' "$out_ok" | grep -q 'ICMP checksum invalid'; then
    fail "happy path must not produce a checksum-invalid log"
fi

# 2. Corruption path. ping-bad fires 3 valid pings then 1 bad-csum
# ping at seq=99. The receiver MUST log "ICMP checksum invalid"
# AND must NOT send back any reply for that seq.
out_bad="$(printf 'run node R0_re ping-bad 20.1.1.2\nquit\n' | ./testapp)"

# Positive: the 3 valid pings still round-trip.
assert_contains "$out_bad" "Ping reply : R0_re : seq=3 from 20.1.1.2"      "3 valid pings still round-trip"

# Positive: the bad-csum ping fires the drop log on R1.
assert_contains "$out_bad" "Ping recv : R1_re : ICMP checksum invalid"     "R1 drops the corrupted echo request"

# Strong gate: no reply for seq=99 ever lands on R0.
if printf '%s\n' "$out_bad" | grep -qE '^Ping reply : R0_re : seq=99 '; then
    fail "no reply must arrive for the corrupted seq=99 (receiver should have dropped)"
fi

# Exact-count: at least one "checksum invalid" line. We don't
# assert exactly 1 because ARP-retry on cold cache could in theory
# replay the bad packet.
n_drops=$(printf '%s\n' "$out_bad" | grep -c 'ICMP checksum invalid' || true)
if [ "$n_drops" -lt 1 ]; then
    fail "expected >=1 checksum-invalid drop, got $n_drops"
fi

pass
