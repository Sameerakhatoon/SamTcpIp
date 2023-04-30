#!/usr/bin/env bash
# ch42: Milestone 4 sign-off (real-wire robustness).
#
# Combined smoke pulling in the three pieces that close M4:
#   ch34  IP fragmentation + reassembly
#   ch39  PMTUD path cache + ICMP Frag Needed receive
#   ch40  TCP cwnd / slow start / loss event
#   ch41  TCP peer-window enforcement
#
# This test does NOT introduce new mechanics; it proves the
# four already-shipped pieces survive being driven together.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=$(printf '
config node R1_re tcp-listen 80
run node R0_re ping 20.1.1.2
run tcp-rwnd 100
run node R0_re tcp-syn 20.1.1.2 80
run node R0_re tcp-send-big 20.1.1.2 80 200
run node R0_re tcp-send-big 20.1.1.2 80 40
run node R0_re tcp-send-big 20.1.1.2 80 40
run node R0_re tcp-loss 20.1.1.2 80
run pmtu set 20.1.1.2 60
run node R0_re udp-big 20.1.1.2 250
run pmtu clear
quit
' | ./testapp 2>&1)

# ch34 - IP fragmentation still works on the post-loss UDP burst.
n_emit=$(echo "$OUT" | grep -c '^IP frag emit : R0_re :' || true)
[ "$n_emit" -ge 6 ] || { echo "FAIL: expected >=6 IP frag emits (pmtu=60), got $n_emit"; exit 1; }

# ch39 - PMTUD shrinks the fragment threshold.
echo "$OUT" | grep -q "PMTU install : dst=20.1.1.2 mtu=60" || { echo "FAIL: PMTU install missing"; exit 1; }
echo "$OUT" | grep -q "PMTU clear all" || { echo "FAIL: PMTU clear missing"; exit 1; }

# ch40 - cwnd grew and then loss happened.
echo "$OUT" | grep -q "init cwnd=1460 ssthresh=65535 peer_win=100" || { echo "FAIL: init cwnd"; exit 1; }
echo "$OUT" | grep -q "slow-start ack=" || { echo "FAIL: slow-start growth missing"; exit 1; }
echo "$OUT" | grep -q "LOSS .* cwnd=1460 ssthresh=" || { echo "FAIL: LOSS event missing"; exit 1; }

# ch41 - oversized send blocked, fitting send went through.
echo "$OUT" | grep -q "window-blocked .* len=200 > min(cwnd=1460, peer_win=100)" || { echo "FAIL: 200 not blocked"; exit 1; }
echo "$OUT" | grep -q "data seq=8193 len=40 to 20.1.1.2:80" || { echo "FAIL: 40-byte send did not fire"; exit 1; }

# Regression: original ping still works.
echo "$OUT" | grep -q "Ping reply : R0_re : seq=3 from 20.1.1.2" || { echo "FAIL: ping regression"; exit 1; }

echo "PASS - Milestone 4 (real-wire robustness) signed off"
