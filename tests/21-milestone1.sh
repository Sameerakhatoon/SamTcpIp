#!/usr/bin/env bash
# Ch21: Milestone 1 goal - real-wire interop via TAP.
#
# Milestone 1 reads: "We're on the wire." Specifically:
# - tcpdump on the host shows our stack's frames with correct
#   wire bytes;
# - host kernel ARP reaches us, we answer;
# - we initiate ARP, the host kernel answers.
#
# Strictly bidirectional. This test asserts the BIDIRECTIONAL
# wire is alive: under root we attach the TAP, configure both
# sides, originate a ping, and observe BOTH egress (TAP send)
# AND ingress (TAP recv) frames in the simulator log. The recv
# direction proves the host kernel responded - the wire works
# both ways.
#
# Under non-root we cannot exercise the wire (TAP open is
# privileged); the test runs the regression suite of all prior
# chapters' assertions.
. "$(dirname "$0")/lib.sh"

if [ "$(id -u)" -eq 0 ]; then
    # Full Milestone-1 demo.
    out="$(printf 'run tap attach R0_re samtap0 eth0/0\nrun tap ifup samtap0\nrun tap host-ip samtap0 10.0.0.99 24\nconfig node R0_re interface eth0/0 ip 10.0.0.1 24\nrun node R0_re ping 10.0.0.99\nrun tap detach\nquit\n' | ./testapp)"

    # Phase 0 of the demo: bring-up steps all succeeded.
    assert_contains "$out" "TAP attach : samtap0 -> R0_re/eth0/0 fd="    "TAP attach success"
    assert_contains "$out" "TAP ifup : samtap0 is UP"                   "TAP ifup success"
    assert_contains "$out" "TAP host-ip : samtap0 set to 10.0.0.99/24"  "TAP host-ip success"
    assert_contains "$out" "Intf ip : R0_re/eth0/0 set to 10.0.0.1/24"  "simulator IP reconfigured"
    assert_contains "$out" "GARP : R0_re : announcing 10.0.0.1"          "GARP after IP set"

    # Phase 1: egress visible on the wire.
    n_tap_send=$(printf '%s\n' "$out" | grep -c '^TAP send : ' || true)
    if [ "$n_tap_send" -lt 1 ]; then
        fail "milestone: expected >=1 TAP send line (ARP/ICMP egress invisible)"
    fi

    # Phase 2: ingress visible on the wire. The host kernel's
    # ARP request (in response to our ICMP egress) reaches our
    # recv thread. Without this, the wire is half-broken.
    n_tap_recv=$(printf '%s\n' "$out" | grep -c '^TAP recv : ' || true)
    if [ "$n_tap_recv" -lt 1 ]; then
        fail "milestone: expected >=1 TAP recv line (host kernel never reached our recv thread)"
    fi

    assert_contains "$out" "TAP detach"                                  "clean detach"
else
    # Non-root: full regression suite of prior chapter assertions.
    out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re udp 20.1.1.2\nrun node R0_re ping-bad 20.1.1.2\nrun node R0_re ping-bad-ip 20.1.1.2\nrun node R0_re udp-bad-csum 20.1.1.2\nconfig node R0_re interface eth0/0 ip 10.0.0.1 24\nrun node R0_re arp-announce\nquit\n' | ./testapp)"

    # ch11/12/13 happy paths.
    assert_contains "$out_reg" "Ping reply : R0_re : seq=3 from 20.1.1.2"          "ch11/12 ping"
    assert_contains "$out_reg" "UDP printer : R0_re : port 12345"                  "ch13 UDP"

    # ch11 ICMP bad-csum gate.
    assert_contains "$out_reg" "ICMP checksum invalid"                              "ch11 ICMP csum"
    # ch12 IP bad-csum gate.
    assert_contains "$out_reg" "IP checksum invalid"                                "ch12 IP csum"
    # ch13 UDP bad-csum gate.
    assert_contains "$out_reg" "UDP recv : R1_re : checksum invalid (drop)"        "ch13 UDP csum"

    # ch19/ch20 IP reconfig + GARP.
    assert_contains "$out_reg" "Intf ip : R0_re/eth0/0 set to 10.0.0.1/24"          "ch19 IP set"
    assert_contains "$out_reg" "GARP : R0_re : announcing 10.0.0.1 on eth0/0"        "ch20 GARP follows"
fi

pass
