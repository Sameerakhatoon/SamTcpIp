#!/usr/bin/env bash
# Walk every numbered test in lexical order. Print pass/fail summary.
set -u
cd "$(dirname "$0")/.."

passed=0
failed=0
failed_list=()
for t in tests/[0-9]*.sh; do
    if bash "$t"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        failed_list+=("$(basename "${t%.*}")")
    fi
done

echo
echo "passed: $passed   failed: $failed"
if [ "$failed" -ne 0 ]; then
    echo "failed tests:"
    for t in "${failed_list[@]}"; do
        echo "  $t"
    done
    exit 1
fi
exit 0
