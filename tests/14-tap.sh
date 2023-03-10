#!/usr/bin/env bash
# Ch14: TAP primitive (open / close / send / recv).
#
# First chapter that talks to a real Linux kernel network
# interface. Layer3/tap.{c,h} wraps the standard /dev/net/tun
# dance: open the device, ioctl(TUNSETIFF, IFF_TAP | IFF_NO_PI)
# to request an ethernet-frame TAP without the 4-byte packet-info
# prefix, return the fd.
#
# Permission model:
#   - opening /dev/net/tun is unprivileged (default mode 0666).
#   - the TUNSETIFF ioctl needs CAP_NET_ADMIN. As a regular user,
#     it fails with EPERM (errno=1, "Operation not permitted").
#
# This test covers BOTH execution modes:
#   - non-root: assert the EPERM diagnostic appears. The success-
#     path assertions (TAP opened: ifname=...) are skipped.
#   - root: assert the success path. EPERM should NOT appear.
#
# Detection: `id -u` == 0 means root.
. "$(dirname "$0")/lib.sh"

out="$(printf 'run tap open samtap0\nrun tap close\nquit\n' | ./testapp)"

if [ "$(id -u)" -eq 0 ]; then
    # Root path. The ioctl should succeed.
    assert_contains "$out" "TAP opened : ifname=samtap0 fd=" "root: tap_open succeeds"
    if printf '%s\n' "$out" | grep -q 'errno=1'; then
        fail "root: TAP open should not produce EPERM"
    fi
else
    # Non-root path. The ioctl MUST fail with EPERM, and the
    # printed diagnostic must include both the textual reason and
    # the errno value (1 == EPERM on Linux).
    assert_contains "$out" "TAP ioctl TUNSETIFF failed" "non-root: TAP open diagnostic appears"
    assert_contains "$out" "Operation not permitted"    "non-root: errno is EPERM (text)"
    assert_contains "$out" "errno=1"                    "non-root: errno is EPERM (number)"

    # Negative: the success line must NOT appear when the ioctl failed.
    if printf '%s\n' "$out" | grep -q 'TAP opened : ifname='; then
        fail "non-root: 'TAP opened' must not appear when the ioctl failed"
    fi
fi

# Regression: ch11/ch12/ch13 paths still work (ping + UDP).
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"             "ch11/12 ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"     "ch13 UDP echo regression"

pass
