#!/usr/bin/env bash
# Ch16: send_pkt_out targets the TAP fd.
#
# ch15 brought receive online. ch16 makes the egress symmetric:
# when send_pkt_out is called with an oif that matches the
# TAP-attached interface, the frame is written to the kernel's
# TAP device instead of going through the UDP-loopback simulator
# wire.
#
# Test plan:
#
#   1. Behavior change under root.
#      Attach TAP to R0_re's eth0/0. Ping 20.1.1.2.
#      WITHOUT ch16: R1_re's simulator-side recv would see the
#      frame and reply (the ch10/11 round-trip we know works).
#      WITH ch16: send_pkt_out detects the TAP-attached oif and
#      writes to the kernel TAP, NOT to R1's UDP socket. So
#      R1_re's `Ping recv` log MUST NOT appear, and the egress
#      log `TAP send : ...` MUST appear.
#
#   2. Behavior unchanged when TAP is not attached.
#      Plain ping continues to round-trip through R1.
#
#   3. Non-root: attach fails at TUNSETIFF (ch14), no behavior
#      change, full simulator round-trip continues.
. "$(dirname "$0")/lib.sh"

if [ "$(id -u)" -eq 0 ]; then
    # Root path - the behavior change is visible.
    out_tap="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun node R0_re ping 20.1.1.2\nrun tap detach\nquit\n' | ./testapp)"

    # Positive: send_pkt_out routed through TAP.
    n_tap_send=$(printf '%s\n' "$out_tap" | grep -c '^TAP send : .* bytes via R0_re/eth0/0' || true)
    if [ "$n_tap_send" -lt 1 ]; then
        fail "expected >=1 'TAP send' line (got $n_tap_send) - send_pkt_out did not route via TAP"
    fi

    # Strong gate: R1_re must NOT process the ping. The
    # simulator's UDP-loopback wire didn't carry it.
    if printf '%s\n' "$out_tap" | grep -q 'Ping recv : R1_re : ICMP echo request'; then
        fail "R1_re must NOT see the ping when TAP is attached - the frame went to kernel TAP"
    fi
    if printf '%s\n' "$out_tap" | grep -qE '^Ping reply : R0_re : seq=[0-9]+ from 20.1.1.2'; then
        fail "no reply must arrive (R1 wasn't reached; kernel has no listener configured)"
    fi
else
    # Non-root path - attach fails, behavior unchanged.
    out_tap="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun node R0_re ping 20.1.1.2\nrun tap detach\nquit\n' | ./testapp)"
    assert_contains "$out_tap" "TAP ioctl TUNSETIFF failed"          "non-root: attach diagnostic"

    # Ping still round-trips normally because attach failed -
    # send_pkt_out's TAP branch sees `tap_is_attached_iif == false`.
    assert_contains "$out_tap" "Ping reply : R0_re : seq=3 from 20.1.1.2" "non-root: ping still works"
    if printf '%s\n' "$out_tap" | grep -q '^TAP send :'; then
        fail "non-root: TAP send line must not appear (attach failed; no fd)"
    fi
fi

# Regression: without any TAP interaction, all prior chapter
# tests continue to pass via the UDP-loopback wire.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"            "ch11/12 ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"    "ch13 UDP regression"
if printf '%s\n' "$out_reg" | grep -q '^TAP send :'; then
    fail "no TAP traffic should be logged when TAP is never attached"
fi

pass
