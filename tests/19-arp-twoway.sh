#!/usr/bin/env bash
# Ch19: ARP two-way over TAP + runtime IP CLI.
#
# The existing ch5 ARP code already handles both directions
# (recv via L2 dispatch on Ethernet type=ARP; send via
# send_pkt_out which ch16 routes to TAP when oif is TAP-attached).
# ch19 adds the missing piece: a runtime CLI to reconfigure the
# simulator-side IP so we can align it with the host-side subnet
# ch18 set up.
#
# New CLI: config node <node> interface <if> ip <ip> <mask>.
#
# Test plan:
#   1. CLI works: reconfigure R0_re's eth0/0 to 10.0.0.1/24,
#      verify the routing table picks up the new direct route.
#   2. Under root: attach + ifup + host-ip 10.0.0.99/24 +
#      reconfigure simulator IP to 10.0.0.1/24 + ping 10.0.0.99.
#      The ARP request goes out the TAP, kernel answers, ping
#      completes round-trip.
#   3. Under non-root: skip the kernel-side path; verify CLI
#      regression only.
. "$(dirname "$0")/lib.sh"

# 1. Reconfigure + verify the FIB update.
out_cfg="$(printf 'config node R0_re interface eth0/0 ip 10.0.0.1 24\nshow node R0_re route\nquit\n' | ./testapp)"
assert_contains "$out_cfg" "Intf ip : R0_re/eth0/0 set to 10.0.0.1/24" "CLI reconfig logged"
# The direct route should reflect the new prefix.
assert_contains "$out_cfg" "10.0.0.0"        "FIB carries the new 10.0.0.0/24 direct route"

# 2. Root: full TAP + ARP + ping demo.
if [ "$(id -u)" -eq 0 ]; then
    out_root="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun tap ifup samtap0\nrun tap host-ip samtap0 10.0.0.99 24\nconfig node R0_re interface eth0/0 ip 10.0.0.1 24\nrun node R0_re ping 10.0.0.99\nrun tap detach\nquit\n' | ./testapp)"

    # ARP went out via TAP (and possibly came back from the kernel).
    assert_contains "$out_root" "TAP send : " "root: ARP/ICMP egress via TAP"

    # We received SOMETHING back via TAP (kernel's ARP reply at minimum).
    n_recv=$(printf '%s\n' "$out_root" | grep -c '^TAP recv :' || true)
    if [ "$n_recv" -lt 1 ]; then
        fail "root: expected >=1 TAP recv frame (kernel-side ARP reply at minimum)"
    fi
fi

# 3. Regression: prior tests still work without TAP.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"            "ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"    "UDP regression"

pass
