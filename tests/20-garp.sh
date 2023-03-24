#!/usr/bin/env bash
# Ch20: gratuitous ARP on IP assignment.
#
# send_gratuitous_arp builds an ARP REPLY with src_ip == dst_ip
# == oif's IP and broadcast target MAC. Peers (including the
# Linux kernel on the TAP side) populate their ARP caches without
# waiting for an active resolution. RFC 5227 sec 2.3 "Announcement".
#
# Hooks:
#   - config node X interface <if> ip <ip> <mask> now fires GARP
#     after the IP set succeeds.
#   - run node X arp-announce iterates over every L3 interface
#     and emits one.
#
# Test plan:
#   1. arp-announce fires GARP on every L3 interface (2 by
#      default in first_topo).
#   2. Reconfiguring an IP via the config CLI ALSO fires GARP.
#   3. Under root: with TAP attached, the GARP frame appears as a
#      TAP send line - meaning the announcement reaches the host
#      kernel.
#   4. Regression: ping + UDP still pass.
. "$(dirname "$0")/lib.sh"

# 1. Manual arp-announce.
out_manual="$(printf 'run node R0_re arp-announce\nquit\n' | ./testapp)"
assert_contains "$out_manual" "GARP : R0_re : announcing 20.1.1.1 on eth0/0"       "GARP on eth0/0"
assert_contains "$out_manual" "GARP : R0_re : announced on 2 interface(s)"         "summary count"

# 2. config-IP triggers GARP.
out_cfg="$(printf 'config node R0_re interface eth0/0 ip 10.0.0.1 24\nquit\n' | ./testapp)"
assert_contains "$out_cfg" "Intf ip : R0_re/eth0/0 set to 10.0.0.1/24" "IP set logged"
assert_contains "$out_cfg" "GARP : R0_re : announcing 10.0.0.1 on eth0/0" "GARP follows IP change"

# 3. Root: TAP send carries the GARP.
if [ "$(id -u)" -eq 0 ]; then
    out_root="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun node R0_re arp-announce\nrun tap detach\nquit\n' | ./testapp)"
    assert_contains "$out_root" "GARP : R0_re : announcing 20.1.1.1 on eth0/0" "root: GARP fired"
    # The GARP emit goes through send_pkt_out -> TAP, logged as TAP send.
    n_tap=$(printf '%s\n' "$out_root" | grep -c '^TAP send : ' || true)
    if [ "$n_tap" -lt 1 ]; then
        fail "root: GARP must produce a TAP send line"
    fi
fi

# 4. Regression.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"           "ping regression"
assert_contains "$out_reg" "UDP printer : R0_re : port 12345 from 20.1.1.2:7"   "UDP regression"

pass
