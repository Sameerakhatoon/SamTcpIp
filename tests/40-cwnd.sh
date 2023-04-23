#!/usr/bin/env bash
# ch40: TCP congestion control (cwnd + slow start + loss).
#
# Verify:
#   - cwnd initialises to peer_mss on ESTABLISHED
#   - each pure ACK grows cwnd by ~peer_mss in slow start
#   - tcp-loss halves cwnd into ssthresh, drops cwnd to one SMSS
#   - tcp dump prints the new accounting fields
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=$(printf '
config node R1_re tcp-listen 80
run node R0_re ping 20.1.1.2
run node R0_re tcp-syn 20.1.1.2 80
run node R0_re tcp-send 20.1.1.2 80 a
run node R0_re tcp-send 20.1.1.2 80 b
run node R0_re tcp-send 20.1.1.2 80 c
show node R0_re tcp
run node R0_re tcp-loss 20.1.1.2 80
show node R0_re tcp
quit
' | ./testapp 2>&1)

# Established with cwnd reported.
echo "$OUT" | grep -q "init cwnd=1460 ssthresh=65535 peer_win=1024" || { echo "FAIL: init cwnd not 1460"; exit 1; }

# Three slow-start ACKs growing cwnd: 2920, 4380, 5840.
echo "$OUT" | grep -q "slow-start ack=8194 acked=1 cwnd=2920" || { echo "FAIL: cwnd not 2920 after first ACK"; exit 1; }
echo "$OUT" | grep -q "slow-start ack=8195 acked=1 cwnd=4380" || { echo "FAIL: cwnd not 4380 after second ACK"; exit 1; }
echo "$OUT" | grep -q "slow-start ack=8196 acked=1 cwnd=5840" || { echo "FAIL: cwnd not 5840 after third ACK"; exit 1; }

# tcp dump shows the new fields.
echo "$OUT" | grep -q "cwnd=5840 ssthresh=65535" || { echo "FAIL: dump didn't print cwnd/ssthresh pre-loss"; exit 1; }

# Loss event: cwnd back to 1460, ssthresh = max(flight/2, 2*MSS) = 2920.
echo "$OUT" | grep -q "LOSS .* cwnd=1460 ssthresh=2920" || { echo "FAIL: loss math wrong"; exit 1; }
echo "$OUT" | grep -q "cwnd=1460 ssthresh=2920" || { echo "FAIL: dump didn't print post-loss state"; exit 1; }

echo "PASS"
