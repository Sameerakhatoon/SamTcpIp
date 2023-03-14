#!/usr/bin/env bash
# Ch15: TAP recv thread wired into pkt_receive.
#
# ch14 shipped open/close primitives. ch15 makes TAP useful by
# spawning a background recv thread that loops on tap_recv_raw
# and hands every frame to pkt_receive(node, iif, ...). The
# kernel side of the TAP is now talking to our L2 ingress.
#
# CLI:
#   run tap attach <node> <ifname> <iif>
#       open the TAP, bind it to (node, iif) on the topology, start
#       the recv thread.
#   run tap detach
#       set the stop flag, join the thread, close the fd.
#
# Permission model identical to ch14:
#   - non-root: tap_open fails with EPERM, attach reports the same
#     diagnostic and does not start a thread.
#   - root: full attach succeeds; recv thread runs idle (no frames
#     arrive without `ip link set up dev samtap0` + a peer).
#
# We assert per-mode and skip the root-only success paths under
# non-root, same as ch14.
. "$(dirname "$0")/lib.sh"

out="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun tap detach\nquit\n' | ./testapp)"

if [ "$(id -u)" -eq 0 ]; then
    # Root path.
    assert_contains "$out" "TAP attach : samtap0 -> R0_re/eth0/0 fd="    "root: attach success line"
    assert_contains "$out" "TAP recv thread started"                     "root: recv thread spawned"
    assert_contains "$out" "TAP recv thread exited"                      "root: recv thread exited cleanly on detach"
    assert_contains "$out" "TAP detach"                                  "root: detach acknowledged"
    if printf '%s\n' "$out" | grep -q 'errno=1'; then
        fail "root: attach should not produce EPERM"
    fi
else
    # Non-root path: attach is rejected at the TUNSETIFF ioctl;
    # neither the success line nor the thread-started log appear.
    assert_contains "$out" "TAP ioctl TUNSETIFF failed"     "non-root: attach diagnostic appears"
    assert_contains "$out" "Operation not permitted"        "non-root: errno is EPERM (text)"
    assert_contains "$out" "errno=1"                        "non-root: errno is EPERM (number)"

    if printf '%s\n' "$out" | grep -q 'TAP attach : samtap0'; then
        fail "non-root: 'TAP attach' must not appear when the ioctl failed"
    fi
    if printf '%s\n' "$out" | grep -q 'TAP recv thread started'; then
        fail "non-root: recv thread must not start without an open fd"
    fi
fi

# Double-attach guard: a second attach without a detach must fail.
# Under non-root the first attach already failed; the second has
# nothing to collide with. Skip that branch.
if [ "$(id -u)" -eq 0 ]; then
    out_double="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun tap attach R0_re samtap1 eth0/0\nrun tap detach\nquit\n' | ./testapp)"
    assert_contains "$out_double" "TAP attach failed : already attached" "double-attach is rejected"
fi

# Bad iif name: attach to a Node that doesn't have the named iif.
out_badif="$(printf 'run tap attach R0_re samtap0 eth9/9\nquit\n' | ./testapp)"
if [ "$(id -u)" -eq 0 ]; then
    assert_contains "$out_badif" "TAP attach failed : no such interface \`eth9/9\` on node R0_re" "bad iif rejected"
fi

# Regression: ch11/ch12/ch13 paths still work.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"            "ch11/12 ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"    "ch13 UDP regression"

pass
