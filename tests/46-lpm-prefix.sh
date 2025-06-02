#!/usr/bin/env bash
# Chapter 44: longest prefix match compares the whole
# prefix.
#
# l3rib_lookup_lpm masks the destination with each route's mask and
# compares the result with the route's prefix as strings. It compared
# only strlen(masked) bytes, so 30.1.1.1 (masked to /32: "30.1.1.1")
# matched a route for 30.1.1.10/32 ("30.1.1.1" is its first 8 bytes)
# and, being /32, won over the right /24.
#
# R0_re: 30.1.1.10/32 via R2_re (40.1.1.2), 30.1.1.0/24 via R1_re.
# A ping to 30.1.1.1 (R1_re itself) must take the /24, straight to
# R1_re: R2_re forwards nothing and R0_re never ARPs for 40.1.1.2.
.  "$(dirname "$0")/lib.sh"

out="$(printf '%s\n' \
    'config node R0_re route 30.1.1.10 32 40.1.1.2 eth0/4' \
    'config node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0' \
    'run node R0_re ping 30.1.1.1' \
    'show node R2_re l3-stats' \
    'quit' | ./testapp 2>&1)"

assert_contains "$out" "Ping reply : R0_re : seq=3 from 20.1.1.2 ttl=64" "reply straight from R1_re (its eth0/1 address)"
assert_contains "$out" "L3 stats : R2_re : forward=on forwarded=0" "nothing went through R2_re"
case "$out" in
    *"ARP miss for 40.1.1.2"*) fail "the /32 route for 30.1.1.10 was taken for 30.1.1.1" ;;
esac

pass
