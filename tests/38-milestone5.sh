#!/usr/bin/env bash
# ch38: Milestone 5 sign-off
#
# Combined operational hygiene smoke:
#   - ch37 log filter active (set to warn)
#   - ch35 arp aging knob set + age cmd works
#   - ch36 clean shutdown on SIGTERM
#   - regression: ping still works under the log filter
set -euo pipefail
cd "$(dirname "$0")/.."

FIFO=$(mktemp -u)
mkfifo "$FIFO"
exec 3<>"$FIFO"

./testapp <&3 >/tmp/m5.out 2>&1 &
PID=$!
sleep 0.4

send(){ printf '%s\n' "$1" >&3; }

# raise filter so default chatter goes quiet
send "run log-level warn"
sleep 0.2

# regression: ping should still work
send "run node R0_re ping 20.1.1.2"
sleep 0.4

# ch35 aging knob - should not crash
send "run node R0_re arp age 1000"
sleep 0.2

# ch37 - prove warn filter active: log-test emits W/E only
send "run log-test"
sleep 0.2

# ch36 - SIGTERM
kill -TERM "$PID"
wait "$PID" || true
exec 3>&-
rm -f "$FIFO"

# verify
OUT=$(cat /tmp/m5.out)

# log filter respected (no [I] line from log-test)
LT=$(echo "$OUT" | sed -n '/log-level : set to warn/,/Received signal/p')
echo "$LT" | grep -q '\[W\] warn-line'  || { echo "FAIL: warn-line missing"; exit 1; }
echo "$LT" | grep -q '\[E\] error-line' || { echo "FAIL: error-line missing"; exit 1; }
if echo "$LT" | grep -q '\[I\] info-line'; then
    echo "FAIL: INFO leaked past warn filter"; exit 1
fi

# ping regression
echo "$OUT" | grep -q "Ping reply" || { echo "FAIL: ping regression"; exit 1; }

# clean shutdown
echo "$OUT" | grep -q "Received signal 15" || { echo "FAIL: SIGTERM not caught"; exit 1; }
echo "$OUT" | grep -q "shutting down cleanly" || { echo "FAIL: no shutdown line"; exit 1; }

echo "PASS - Milestone 5 (operational hygiene) signed off"
