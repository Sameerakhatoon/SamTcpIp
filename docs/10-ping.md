# ch10 - ping application

## What landed

- L3 gained a per-protocol L4 handler registry:
  `l3_register_l4_handler(proto, fn)` installs a callback indexed
  by the IP `protocol` field. `promote_pkt_to_layer4` looks it up
  after stripping the IP header; falls back to the ch9 printf
  stub if no handler is registered.
- New module `Layer5/ping.{c,h}`:
  - `PingMsg { type, seq, origin_ip }` (packed) carried as the IP
    payload under `PING_PROTO = 201`.
  - `ping_register()` wires `ping_recv` into the L4 registry.
  - `ping_send_request(node, dst_ip_str, seq)` originates a REQ.
  - `ping_recv`: REQ -> emit REPLY back to inbound src_ip; REPLY
    -> print `Ping reply : <node> : seq=N from <src>`.
- `run node <name> ping <ip>` CLI now uses the ping app (3 seq
  sends with sleeps), so the second attempt seeds R1's ARP cache
  for the reply path and the third round-trips cleanly.

## Source-IP selection (the fix that made the round-trip work)

First cut at the ping handler echoed the REPLY back to the
inbound src_ip - which was the originator's loopback (122.1.1.0)
because ch9's `demote_packet_to_layer3` chose loopback as src by
default. R1_re has no route to 122.1.1.0 (no default gateway, no
loopback redistribution), so every reply dropped with "no route".

Fix in `demote_packet_to_layer3`: pick src_ip from the outgoing
interface, not the loopback. Logic:

- direct route -> src = `node_get_matching_subnet_interface(dst)->IF_IP`
- indirect route -> src = `route->oif`'s IF_IP
- nothing else available -> fall back to loopback (preserves the
  ch9 behavior for self-addressed packets)

This mirrors how a real host picks src per the routing decision.
Reply now lands on R0_re because R1_re has a direct route to
20.1.1.0/24 (R0_re's eth0/0).

## ARP-miss + originate count

The L3 forwarding pipeline drops on ARP miss and fires a
broadcast (ch9 doc explains why). For the ping CLI to "just
work" without forcing the user to run `resolve-arp` first, we
fire 3 REQ pings with 200ms sleeps:

- seq 1 -> ARP miss outbound, R0 broadcasts, packet drops; R0
  receives reply for the ARP exchange and seeds cache.
- seq 2 -> reaches R1; R1's REPLY hits ARP miss on its side and
  broadcasts back to R0; reply drops; R1's cache now seeded.
- seq 3 -> full round-trip; "Ping reply" prints.

A real `ping` would use a longer timeout + sequence-based retry.
Three shots is the smallest count that survives the two ARP-
miss rounds while keeping the test fast (sub-second).

## Why a new protocol number (201) instead of reusing ICMP=1

The book's model is "L4 handler keyed by IP protocol field" and
nothing in our stack actually parses ICMP wire format. Picking
201 (an unassigned IANA range value) makes it obvious we're
running our own protocol on top of the same dispatch mechanism.
Reusing `1` would just be cosmetic.

## End-to-end demo

```
samtcpip> run node R0_re ping 20.1.1.2
L3 send : R0_re : ARP miss for 20.1.1.2, firing broadcast on eth0/0
... (ARP exchange) ...
Ping recv : R1_re : REQ seq=2 from 20.1.1.1, sending REPLY
L3 send : R1_re : ARP miss for 20.1.1.1, firing broadcast on eth0/1
... (return-path ARP exchange) ...
Ping recv : R1_re : REQ seq=3 from 20.1.1.1, sending REPLY
Ping reply : R0_re : seq=3 from 20.1.1.2
```

## Beyond the book

ch10 in the book also gestures at traceroute. Skipped for now;
the L4 registry makes it straightforward to add later (new
protocol number + TTL-decrement handler at each hop returning a
diagnostic), but it doesn't teach anything new about the stack.
The book ends here. Next steps are open-ended: bring up a 3-hop
forwarding test, add a real ICMP wire format, build TCP/UDP,
etc.
