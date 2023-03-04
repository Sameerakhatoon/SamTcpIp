#!/usr/bin/env bash
# Ch12: real 20-byte IPv4 header + RFC 1071 IP checksum.
#
# The course shipped IpHdr at 22 bytes (ttl/protocol/checksum
# were `short`). ch12 fixes to RFC 791 exactly:
#   - sizeof(IpHdr) == 20 (pinned by _Static_assert in layer3.c)
#   - tos / ttl / protocol are 1 byte each
#   - checksum is computed on originate (demote_packet_to_layer3)
#     and recomputed on TTL decrement (forward path)
#   - receiver verifies with inet_checksum over the whole 20-byte
#     header (RFC 1071 self-consistency: valid yields 0); a bad
#     csum drops the packet at L3, BEFORE the L4 dispatch fires
#
# This test exercises three paths:
#
#   1. Happy round-trip - real IP + real ICMP, both checksums
#      pass, ping replies as ch11.
#
#   2. Corrupted IP checksum - the originator XORs one bit of the
#      IP csum after compute. Receiver MUST log "L3 drop : ... IP
#      checksum invalid" and the corrupted packet's L4 (ICMP) MUST
#      NOT be processed.
#
#   3. ch11 ICMP regression - clean ICMP path still works alongside
#      the new IP-csum logic.
. "$(dirname "$0")/lib.sh"

# 1. Happy round-trip.
out_ok="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_ok" "Ping recv : R1_re : ICMP echo request seq="     "ICMP request lands"
assert_contains "$out_ok" "Ping reply : R0_re : seq=3 from 20.1.1.2"       "round-trip reply"
if printf '%s\n' "$out_ok" | grep -q 'IP checksum invalid'; then
    fail "clean ping must not trigger IP-csum drop"
fi

# 2. Bad IP checksum. ping-bad-ip fires 3 clean pings then 1 with
# the IP csum corrupted (seq=88). The seq=88 ICMP MUST never reach
# R1's ICMP handler.
out_bad="$(printf 'run node R0_re ping-bad-ip 20.1.1.2\nquit\n' | ./testapp)"

# Positive: clean pings still round-trip.
assert_contains "$out_bad" "Ping reply : R0_re : seq=3 from 20.1.1.2"      "3 valid pings still round-trip"

# Positive: the bad packet fires the L3 drop log.
assert_contains "$out_bad" "L3 drop : R1_re : IP checksum invalid"         "R1 drops corrupted IP header"

# Strong gate: seq=88 (the corrupted ping) NEVER appears in any
# ICMP recv log on R1. The L3 drop must short-circuit before L4.
if printf '%s\n' "$out_bad" | grep -qE 'ICMP echo request seq=88'; then
    fail "L3 drop must short-circuit BEFORE ICMP dispatch; seq=88 must not reach R1's ICMP handler"
fi

# Negative: no ICMP-csum drop log appears - the IP csum gate
# fires first and the receiver never reaches the ICMP layer.
if printf '%s\n' "$out_bad" | grep -q 'ICMP checksum invalid'; then
    fail "IP-csum drop must come BEFORE ICMP-csum verify; ICMP layer should not even see the packet"
fi

# Exact count: at least one IP-csum drop.
n=$(printf '%s\n' "$out_bad" | grep -c 'L3 drop : R1_re : IP checksum invalid' || true)
if [ "$n" -lt 1 ]; then
    fail "expected >=1 IP-csum drop, got $n"
fi

# 3. ch11 regression - ICMP bad-csum still drops at the ICMP
# layer (the IP csum is correct on a ping-bad ping; only the
# ICMP csum is flipped).
out_ch11="$(printf 'run node R0_re ping-bad 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_ch11" "Ping recv : R1_re : ICMP checksum invalid"    "ch11 ICMP-csum drop still works"
if printf '%s\n' "$out_ch11" | grep -q 'IP checksum invalid'; then
    fail "ch11 fixture must not trigger IP-csum drop (only ICMP csum is corrupted)"
fi

pass
