#!/usr/bin/env bash
# ch37: log level discipline
#
# Verify:
#   - default level INFO: log-test emits I/W/E (no D)
#   - log-level warn: log-test emits W/E only
#   - log-level debug: log-test emits D/I/W/E
#   - log-level error: log-test emits E only
#   - unknown level rejected
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=$(printf 'run log-test\nrun log-level warn\nrun log-test\nrun log-level debug\nrun log-test\nrun log-level error\nrun log-test\nrun log-level lolwut\nquit\n' | ./testapp 2>&1)

# slice on "set to" markers (the prompt eats the typed verb so we can't grep "log-test")
blk1=$(echo "$OUT" | sed -n '1,/log-level : set to warn/p')
blk2=$(echo "$OUT" | sed -n '/log-level : set to warn/,/log-level : set to debug/p')
blk3=$(echo "$OUT" | sed -n '/log-level : set to debug/,/log-level : set to error/p')
blk4=$(echo "$OUT" | sed -n '/log-level : set to error/,/log-level : unknown/p')

# block 1 = default INFO
echo "$blk1" | grep -q '\[I\] info-line'  || { echo "FAIL: blk1 missing I"; exit 1; }
echo "$blk1" | grep -q '\[W\] warn-line'  || { echo "FAIL: blk1 missing W"; exit 1; }
echo "$blk1" | grep -q '\[E\] error-line' || { echo "FAIL: blk1 missing E"; exit 1; }
if echo "$blk1" | grep -q '\[D\] debug-line'; then
    echo "FAIL: DEBUG leaked at default INFO"; exit 1
fi

# block 2 = warn
echo "$blk2" | grep -q '\[W\] warn-line'  || { echo "FAIL: blk2 missing W"; exit 1; }
echo "$blk2" | grep -q '\[E\] error-line' || { echo "FAIL: blk2 missing E"; exit 1; }
if echo "$blk2" | grep -qE '\[D\] debug-line|\[I\] info-line'; then
    echo "FAIL: DEBUG/INFO leaked at WARN"; exit 1
fi

# block 3 = debug
echo "$blk3" | grep -q '\[D\] debug-line' || { echo "FAIL: blk3 missing D"; exit 1; }
echo "$blk3" | grep -q '\[I\] info-line'  || { echo "FAIL: blk3 missing I"; exit 1; }
echo "$blk3" | grep -q '\[W\] warn-line'  || { echo "FAIL: blk3 missing W"; exit 1; }
echo "$blk3" | grep -q '\[E\] error-line' || { echo "FAIL: blk3 missing E"; exit 1; }

# block 4 = error
echo "$blk4" | grep -q '\[E\] error-line' || { echo "FAIL: blk4 missing E"; exit 1; }
if echo "$blk4" | grep -qE '\[D\] debug-line|\[I\] info-line|\[W\] warn-line'; then
    echo "FAIL: lower levels leaked at ERROR"; exit 1
fi

# unknown name rejected
echo "$OUT" | grep -q "log-level : unknown" || { echo "FAIL: unknown not rejected"; exit 1; }

echo "PASS"
