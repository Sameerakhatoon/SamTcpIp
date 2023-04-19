#!/usr/bin/env bash
# Ch36: signal handling + clean shutdown.
#
# Without SIGINT/SIGTERM handlers, Ctrl-C from a terminal mostly
# Just Worked (the shell killed the process) but left the kernel
# TAP interface dangling, and any active pcap file truncated.
# ch36 installs sigaction handlers that:
#   - tap_detach (if attached)
#   - pcap_close_file (flush + close)
#   - exit cleanly via _exit(0)
#
# Test plan:
#   1. Start testapp in the background with stdin held open via a fifo.
#   2. Send SIGINT.
#   3. Assert the goodbye log line appears + exit code is 0.
. "$(dirname "$0")/lib.sh"

# stdin via a fifo so cli_repl doesn't exit on EOF.
FIFO=/tmp/samtcpip-ch36-fifo
LOG=/tmp/samtcpip-ch36-log
rm -f "$FIFO" "$LOG"
mkfifo "$FIFO"
# Hold the fifo open from a sleeping subshell.
exec 9<>"$FIFO"

./testapp <&9 > "$LOG" 2>&1 &
TP=$!

sleep 0.3
if ! kill -INT "$TP" 2>/dev/null; then
    fail "testapp exited before we could signal it"
fi

# Wait for the process; expect a clean exit.
wait "$TP"
RC=$?

exec 9<&-
rm -f "$FIFO"

# Positive: goodbye line landed.
assert_contains "$(cat "$LOG")" "Received signal 2 - shutting down cleanly" "SIGINT handler fired"

# Strong gate: exit code 0 (our handler calls _exit(0)).
if [ "$RC" -ne 0 ]; then
    fail "expected exit code 0 after clean shutdown; got $RC"
fi

rm -f "$LOG"

# Also: SIGTERM works the same way.
mkfifo "$FIFO"
exec 9<>"$FIFO"
./testapp <&9 > "$LOG" 2>&1 &
TP=$!
sleep 0.3
kill -TERM "$TP" 2>/dev/null
wait "$TP"
RC=$?
exec 9<&-
rm -f "$FIFO"
assert_contains "$(cat "$LOG")" "Received signal 15 - shutting down cleanly" "SIGTERM handler fired"
if [ "$RC" -ne 0 ]; then
    fail "expected exit code 0 after SIGTERM; got $RC"
fi
rm -f "$LOG"

# Regression: normal CLI quit still works end-to-end.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2" "ping regression"

pass
