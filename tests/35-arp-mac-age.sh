#!/usr/bin/env bash
# Ch35: ARP + MAC table aging.
#
# Milestone 5 begins. ArpEntry + MacTableEntry gain
# last_seen_ms. The field is set on install and refreshed on
# every lookup hit (so entries in active use never age out).
#
# arp_age(table, threshold_ms) walks + removes entries older
# than threshold; mac_age is symmetric.
#
# CLI: run node X arp-age <ms>, run node X mac-age <ms>.
#
# Test plan:
#   1. After a ping, R0's ARP table has 20.1.1.2.
#   2. arp-age with a huge threshold removes nothing (entry
#      is fresh).
#   3. arp-age with threshold=1ms removes the entry (it has
#      aged out).
#   4. After removal, show node X arp doesn't include it.
.  "$(dirname "$0")/lib.sh"

# 1+2+3: install + no-age + age-out cycle.
out="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re arp-age 100000\nshow node R0_re arp\nrun node R0_re arp-age 1\nshow node R0_re arp\nquit\n' | ./testapp)"

# No-age removes 0.
assert_contains "$out" "ARP age : R0_re : removed 0 stale entry(s) (threshold=100000ms)" "fresh entry not aged"

# Tight threshold removes 1.
assert_contains "$out" "ARP age : R0_re : removed 1 stale entry(s) (threshold=1ms)" "stale entry aged out"

# Aging diagnostic line names the IP that timed out.
assert_contains "$out" "ARP age : 20.1.1.2 : timeout age=" "diagnostic names the IP"

# Strong gate: the post-aging show MUST NOT contain 20.1.1.2.
# Slice after the second arp-age call.
post=$(printf '%s\n' "$out" | awk '/ARP age : R0_re : removed 1/{f=1;next} f')
if printf '%s\n' "$post" | grep -q '20\.1\.1\.2'; then
    fail "post-age show must not contain 20.1.1.2 (it was just removed)"
fi

# Regression: ping after the removal re-installs it.
out_reg="$(printf 'run node R0_re ping 20.1.1.2\nrun node R0_re arp-age 1\nrun node R0_re ping 20.1.1.2\nshow node R0_re arp\nquit\n' | ./testapp)"
n_arp_entries=$(printf '%s\n' "$out_reg" | grep -c '20\.1\.1\.2' || true)
if [ "$n_arp_entries" -lt 1 ]; then
    fail "post-age re-ping should reinstall ARP entry; got $n_arp_entries refs"
fi

pass
