#!/usr/bin/env bash
# Ch5: end-to-end ARP. R0_re fires `resolve-arp 20.1.1.2` (R1_re's
# eth0/1 address). The receiver thread on R1_re processes the
# broadcast request and sends back an ARP reply; R0_re's receiver
# thread processes the reply and adds the entry to R0_re's ARP
# cache. `show node R0_re arp` then lists it. Must be driven via
# the REPL so the ARP cache persists between commands.
. "$(dirname "$0")/lib.sh"

out="$(printf 'run node R0_re resolve-arp 20.1.1.2\nshow node R0_re arp\nquit\n' | ./testapp)"

# Request leg: R1_re saw the broadcast on its eth0/1.
assert_contains "$out" "ARP Broadcast msg recvd on interface eth0/1 of node R1_re" "R1_re saw the request"
# Reply leg: R0_re saw the reply on its eth0/0.
assert_contains "$out" "ARP reply msg recvd on interface eth0/0 of node R0_re"     "R0_re saw the reply"
# Cache update: dump shows the resolved IP and the wire it came in on.
assert_contains "$out" "IP : 20.1.1.2"          "ARP cache holds 20.1.1.2"
assert_contains "$out" "OIF = eth0/0"           "OIF recorded as eth0/0"

# Wrong subnet: nothing on R0_re owns the 99.* subnet, so the send
# path should print the "No eligible subnet" error and the ARP
# cache should be empty.
out2="$(printf 'run node R0_re resolve-arp 99.99.99.99\nshow node R0_re arp\nquit\n' | ./testapp)"
assert_contains "$out2" "No eligible subnet for ARP resolution for Ip-address : 99.99.99.99" "rejects off-subnet IP"

# Wrong target IP within a known subnet: R1_re/eth0/1 IS in 20.1.1.0/24
# but 20.1.1.99 is not assigned to any interface, so R1_re drops the
# request and no reply arrives.
out3="$(printf 'run node R0_re resolve-arp 20.1.1.99\nshow node R0_re arp\nquit\n' | ./testapp)"
assert_contains "$out3" "ARP Broadcast req msg dropped, Dst IP address did not match" "R1_re drops mismatched request"
pass
