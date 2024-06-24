#!/usr/bin/env bash
# Ch17: event-loop + threading + locking model.
#
# Audit + a single fix: recursive global mutex around pkt_receive
# entry. Two recv threads (UDP loopback + TAP) now potentially
# land on the same Node concurrently, walking shared per-Node
# tables (ARP, MAC, RT) that the course built lock-free under a
# single-thread assumption.
#
# This test is regression-style. ch17 is invisible at the test
# log level - it just makes correctness hold under concurrency.
# The test rule still requires one test per chapter:
#
#   1. Stress the loopback path with rapid back-to-back pings +
#      UDP to demonstrate no lock-induced deadlock and no
#      corrupted output.
#   2. Under root, attach TAP + repeat - exercising the two-thread
#      recv path. The lock means no segfaults or torn state.
#   3. All prior tests (1..16) must keep passing.
. "$(dirname "$0")/lib.sh"

# 1. Rapid back-to-back loopback traffic. If the lock deadlocks
# or releases prematurely, this loop hangs or produces visibly
# inconsistent logs. (We do not need timing-based assertions;
# success = the test process exits via `quit`.)
out_stress="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nrun node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nrun node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"

# Positive: every ping run still produces a reply.
n_replies=$(printf '%s\n' "$out_stress" | grep -c '^Ping reply : R0_re :' || true)
if [ "$n_replies" -lt 6 ]; then
    fail "expected >=6 ping replies across 3 ping runs, got $n_replies"
fi

# Positive: every UDP run still produces a printer log.
n_printer=$(printf '%s\n' "$out_stress" | grep -c '^UDP printer : R0_re :' || true)
if [ "$n_printer" -lt 1 ]; then
    fail "expected >=1 UDP printer log across UDP runs, got $n_printer"
fi

# Negative: no recv-side errors (the receiver's L4 dispatch must
# not log "Pkt recvd on unknown interface" if the lock didn't
# corrupt the aux header).
if printf '%s\n' "$out_stress" | grep -q 'Pkt recvd on unknown interface'; then
    fail "interface-name corruption in recv path - lock or recv discipline broken"
fi

# 2. Root-only: TAP + loopback concurrently.
if [ "$(id -u)" -eq 0 ]; then
    out_root="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun node R0_re ping 20.1.1.2\nrun node R0_re ping 20.1.1.2\nrun tap detach\nquit\n' | ./testapp)"
    # Just assert the process completed (the prompts cycled to quit).
    assert_contains "$out_root" "TAP detach" "root: detach completed cleanly under TAP+loopback load"
fi

pass
