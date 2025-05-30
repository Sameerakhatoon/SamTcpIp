#!/usr/bin/env bash
# ch41: TCP real peer-window enforcement.
#
# Verify:
#   - peer_win comes from the SYN-ACK / ACK window field
#   - a chunk that doesn't fit min(cwnd, peer_window) - in_flight is
#     logged as window-blocked and waits in the send buffer (chapter
#     44: it used to be refused); what the window takes
#     goes now, the rest as ACKs open it
#   - a chunk queued behind it follows in order
#   - default rwnd 1024 still works for small sends (regression)
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=$(printf '
run tcp-rwnd 100
config node R1_re tcp-listen 80
run node R0_re ping 20.1.1.2
run node R0_re tcp-syn 20.1.1.2 80
run node R0_re tcp-send-big 20.1.1.2 80 200
run node R0_re tcp-send-big 20.1.1.2 80 50
quit
' | ./testapp 2>&1)

# rwnd CLI reports.
echo "$OUT" | grep -q "TCP rwnd : set to 100" || { echo "FAIL: rwnd CLI missing"; exit 1; }

# Peer's window propagates to client's TCB.
echo "$OUT" | grep -q "init cwnd=1460 ssthresh=65535 peer_win=100" || { echo "FAIL: client didn't pick up peer_win=100"; exit 1; }

# 200-byte send window-blocked (200 > min(1460, 100) - 0): queued.
echo "$OUT" | grep -q "window-blocked in_flight=0 + len=200 > min(cwnd=1460, peer_win=100), queued" \
    || { echo "FAIL: 200-byte send not window-blocked"; exit 1; }

# The window takes 100 bytes at a time; the 50-byte send follows.
echo "$OUT" | grep -q "TCP send : R0_re : data seq=8193 len=100" \
    || { echo "FAIL: first 100 bytes did not go"; exit 1; }
echo "$OUT" | grep -q "TCP send : R0_re : data seq=8293 len=100" \
    || { echo "FAIL: second 100 bytes did not go after the ACK"; exit 1; }
echo "$OUT" | grep -q "TCP send : R0_re : data seq=8393 len=50" \
    || { echo "FAIL: 50-byte send did not go through"; exit 1; }

# Regression: default 1024 still works for small payloads.
OUT2=$(printf '
config node R1_re tcp-listen 80
run node R0_re ping 20.1.1.2
run node R0_re tcp-syn 20.1.1.2 80
run node R0_re tcp-send 20.1.1.2 80 hello
quit
' | ./testapp 2>&1)
echo "$OUT2" | grep -q "TCP send : R0_re : data seq=8193 len=5" \
    || { echo "FAIL: regression 5-byte send"; exit 1; }
echo "$OUT2" | grep -q "init cwnd=1460 ssthresh=65535 peer_win=1024" \
    || { echo "FAIL: regression default peer_win"; exit 1; }

echo "PASS"
