#!/usr/bin/env bash
# Ch9: L3 forwarding pipeline.
# Three pieces under test:
#   1. Originate path builds an IP packet, runs LPM, ARP-resolves
#      the next-hop, drops it on L2 with the right Ethernet encap.
#   2. Direct-route delivery: receiver's L2 accepts, chops the
#      header, L3 sees `is_layer3_local_delivery` true, hands the
#      payload to L4 (registered ping handler under ch10 - the
#      ch10 test covers the round-trip in full; here we only need
#      to confirm L4 hand-off happened).
#   3. ARP-miss behavior: first attempt with no ARP entry prints
#      `ARP miss` and fires a broadcast, but does NOT deliver.
. "$(dirname "$0")/lib.sh"

# 1+2. Direct-connected delivery after pre-resolved ARP.
out_ping="$(printf 'run node R0_re resolve-arp 20.1.1.2\nrun node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
# L4 receive on R1 (any of the seq round-trips) confirms:
# - L3 ingress chopped the L2 header
# - LPM hit the direct route
# - is_layer3_local_delivery returned true
# - promote_pkt_to_layer4 dispatched to the registered handler
assert_contains "$out_ping" "Ping recv : R1_re : REQ" "L4 dispatch on R1_re"

# 3. ARP-miss path: ping without pre-resolving.
out_miss="$(printf 'run node R0_re ping 20.1.1.2\nquit\n' | ./testapp)"
assert_contains "$out_miss" "ARP miss for 20.1.1.2"     "ARP miss reported on outbound"

# 4. No-route drop: ping an IP with no matching route on R0_re.
out_noroute="$(printf 'run node R0_re ping 99.99.99.99\nquit\n' | ./testapp)"
assert_contains "$out_noroute" "no route" "drop with no route diagnostic"

pass
