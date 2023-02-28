#!/usr/bin/env bash
# Ch9: L3 forwarding pipeline.
# Three pieces under test:
#   1. Originate path: `run node X ping <ip>` builds an IP packet on
#      X (src=loopback), runs LPM, ARP-resolves the next-hop, and
#      drops it on L2 with the right Ethernet encap.
#   2. Direct-route delivery: the destination is on a directly
#      connected subnet -> the receiver's L2 accepts, chops the L2
#      header, L3 sees `is_layer3_local_delivery` true, hands the
#      payload to L4 which prints `L4 Packet received ... payload
#      `ping``.
#   3. ARP-miss behavior: first ping with no ARP entry prints
#      `ARP miss` and fires a broadcast, but does NOT deliver the
#      packet (matches reference's drop-and-retry pseudocode).
. "$(dirname "$0")/lib.sh"

# 1+2. Direct-connected ping after pre-resolved ARP.
out_ping="$(printf 'run node R0_re resolve-arp 20.1.1.2\nrun node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_ping" "L4 Packet received : node R1_re" "L4 delivery on R1_re"
assert_contains "$out_ping" "payload \`ping\`"                "ping payload visible at L4"
assert_contains "$out_ping" "proto 2048"                      "L4 sees IP_HDR_TYPE protocol number"

# 3. ARP-miss path: ping without pre-resolving.
out_miss="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_miss" "ARP miss for 20.1.1.2"          "ARP miss reported"
# No L4 delivery on this attempt (reference drops on miss).
if printf '%s\n' "$out_miss" | grep -q 'L4 Packet received'; then
    fail "ARP-miss attempt should NOT deliver"
fi

# 4. No-route drop: ping an IP with no matching route on R0_re.
out_noroute="$(printf 'run node R0_re ping 99.99.99.99\nquit\n' | ./testapp)"
assert_contains "$out_noroute" "no route" "drop with no route diagnostic"

pass
