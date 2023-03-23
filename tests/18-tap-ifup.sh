#!/usr/bin/env bash
# Ch18: static TAP-IP CLI + interface bring-up.
#
# ch14-ch17 left the kernel-side TAP in DOWN with no IP. The
# operator's only path to make the interface useful was
# `sudo ip link set up dev samtap0` + `sudo ip addr add ...`.
# ch18 brings those steps inside the simulator via SIOCSIFFLAGS
# and SIOCSIFADDR / SIOCSIFNETMASK ioctls.
#
# New CLI:
#   run tap ifup <ifname>
#       SIOCGIFFLAGS read + (|= IFF_UP|IFF_RUNNING) + SIOCSIFFLAGS.
#   run tap host-ip <ifname> <ip> <mask-bits>
#       SIOCSIFADDR + SIOCSIFNETMASK.
#
# Test branches on `id -u`:
#   - non-root: both ioctls fail. ifup hits ENODEV when no TAP
#     exists yet (no attach happened); host-ip hits EPERM.
#   - root: full sequence attach + ifup + host-ip + detach
#     succeeds with the new "TAP ifup : ... is UP" and
#     "TAP host-ip : ... set to ..." logs.
. "$(dirname "$0")/lib.sh"

if [ "$(id -u)" -eq 0 ]; then
    # Root path - full bring-up sequence.
    out_root="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun tap ifup samtap0\nrun tap host-ip samtap0 10.0.0.99 24\nrun tap detach\nquit\n' | ./testapp)"
    assert_contains "$out_root" "TAP attach : samtap0 -> R0_re/eth0/0 fd=" "root: attach"
    assert_contains "$out_root" "TAP ifup : samtap0 is UP"                "root: ifup"
    assert_contains "$out_root" "TAP host-ip : samtap0 set to 10.0.0.99/24" "root: host-ip"
    assert_contains "$out_root" "TAP detach"                              "root: detach"

    if printf '%s\n' "$out_root" | grep -qE 'TAP (ifup|host-ip).*errno='; then
        fail "root: no ioctl should produce an errno"
    fi
else
    # Non-root path - both ioctls fail.
    out_nonroot="$(printf 'run tap ifup samtap0\nrun tap host-ip samtap0 10.0.0.99 24\nquit\n' | ./testapp)"

    # ifup without an attached TAP hits ENODEV (no such interface).
    assert_contains "$out_nonroot" "TAP ifup : SIOCGIFFLAGS failed"  "non-root: ifup diagnostic"

    # host-ip fails too. The exact ioctl that errors first depends
    # on kernel order; the diagnostic always names the failing
    # ioctl + the errno.
    assert_contains "$out_nonroot" "TAP host-ip :"                  "non-root: host-ip diagnostic"
    assert_contains "$out_nonroot" "errno="                         "non-root: errno reported"

    # Negative: success lines must NOT appear.
    if printf '%s\n' "$out_nonroot" | grep -q 'is UP'; then
        fail "non-root: 'is UP' must not appear without CAP_NET_ADMIN"
    fi
    if printf '%s\n' "$out_nonroot" | grep -q 'set to 10.0.0.99'; then
        fail "non-root: 'set to ...' must not appear"
    fi
fi

# Regression: existing chapter tests still pass.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2" "ping regression"

pass
