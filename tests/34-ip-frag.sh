#!/usr/bin/env bash
# Ch34: IP fragmentation + reassembly (RFC 791).
#
# Milestone 4 begins. demote splits payloads >
# IP_MAX_FRAG_PAYLOAD (100 bytes) into fragments with proper
# id + frag_offset + MF flag. Receiver indexes pending
# datagrams by (src_ip, dst_ip, proto, id), accumulates,
# delivers on completion.
#
# Test plan:
#   1. 250-byte UDP -> 3 fragments emit on R0 (96 + 96 + 66
#      L3 payload bytes; payload = 8-byte UdpHdr + data).
#   2. R1 reassembles all 3 -> UDP echo handler fires on the
#      full 250-byte payload.
#   3. R1's echo reply ALSO fragments (it's the same size).
#   4. Regression: small payloads (<= 100 bytes) take the
#      single-packet fast path; no IP frag log fires.
. "$(dirname "$0")/lib.sh"

# 1+2+3: large UDP triggers fragmentation both directions.
out="$(printf 'run node R0_re udp-big 20.1.1.2 250\nquit\n' | ./testapp)"

# Emit-side fragments on R0 (3 fragments for 250+8=258 bytes
# of L4 payload: 96 + 96 + 66).
assert_contains "$out" "IP frag emit : R0_re : id=" "R0 emits fragments"
n_emit=$(printf '%s\n' "$out" | grep -c '^IP frag emit : R0_re :' || true)
if [ "$n_emit" -lt 3 ]; then
    fail "expected >=3 emit fragments from R0; got $n_emit"
fi

# Receive-side reassembly on R1.
assert_contains "$out" "IP frag recv : R1_re :" "R1 receives fragments"
assert_contains "$out" "IP frag done : R1_re :" "R1 reassembly completes"

# Echo handler fires on the FULL 250-byte payload (proves
# reassembly delivered correctly).
assert_contains "$out" "UDP echo : R1_re : recv 250 bytes on port 7" "echo handler sees full reassembled payload"

# Reply path also fragments.
assert_contains "$out" "IP frag emit : R1_re :" "R1 echo reply fragments"

# 4. Small payload regression: ping shouldn't fragment.
out_small="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
if printf '%s\n' "$out_small" | grep -q '^IP frag emit'; then
    fail "small payload (ping) must not fragment"
fi
assert_contains "$out_small" "Ping reply : R0_re : seq=3 from 20.1.1.2" "ping regression"

pass
