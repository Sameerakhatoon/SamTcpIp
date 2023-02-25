#!/usr/bin/env bash
# Ch6: L2 mac learning + forwarding. Three hosts (H1, H2, H4) share
# 10.1.1.0/24 via one L2SW running all three ports in ACCESS mode.
# H1 ARPs for H2's IP; the request floods through the switch to H2
# and H4, H4 drops (wrong IP), H2 replies. After the exchange:
#   - H1's ARP cache holds 10.1.1.2 with OIF = eth0/4
#   - L2SW's MAC table holds entries for both H1's eth0/5 (learned
#     from the broadcast) and H2's eth0/7 (learned from the reply)
. "$(dirname "$0")/lib.sh"

out="$(printf 'run node H1 resolve-arp 10.1.1.2\nshow node L2SW mac\nshow node H1 arp\nquit\n' | ./testapp --topo l2switch)"

# Flooding path: every host got the broadcast.
assert_contains "$out" "ARP Broadcast msg recvd on interface eth0/6 of node H2" "H2 got the broadcast"
assert_contains "$out" "ARP Broadcast msg recvd on interface eth0/1 of node H4" "H4 got the broadcast"
assert_contains "$out" "H4 : ARP Broadcast req msg dropped"                    "H4 dropped (wrong IP)"

# Reply leg: H1 saw the unicast reply on its own port.
assert_contains "$out" "ARP reply msg recvd on interface eth0/4 of node H1"    "H1 got the reply"

# MAC table learned both directions.
assert_contains "$out" "Intf : eth0/5" "L2SW learned H1's MAC on eth0/5"
assert_contains "$out" "Intf : eth0/7" "L2SW learned H2's MAC on eth0/7"

# ARP cache on H1 holds the resolved binding.
assert_contains "$out" "IP : 10.1.1.2"  "H1 cached 10.1.1.2"
assert_contains "$out" "OIF = eth0/4"   "H1 cached on eth0/4"
pass
