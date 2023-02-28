# ch9 - L3 forwarding pipeline

## What landed

- `layer3_pkt_recv_from_layer2(node, iif, pkt, pkt_size, proto)` -
  L3 ingress. `pkt` points at the IP header (L2 already chopped).
- Three forwarding outcomes:
  1. **local delivery** (direct route + dst matches a local IP) ->
     chop the IP header and call `promote_pkt_to_layer4`.
  2. **direct subnet** (direct route + dst NOT local) -> push down
     to L2 with no specific oif; L2 picks the interface by subnet
     match on the destination.
  3. **forward** (indirect route) -> decrement TTL, drop if zero,
     otherwise push down to L2 with next-hop = `route->gw_ip` and
     oif = `route->oif`.
- `layer3_pkt_push_down_to_layer2_for_l2routing` does the ARP
  lookup, Ethernet encap (type = IP_HDR_TYPE), and `send_pkt_out`.
  On ARP miss it fires a broadcast request and DROPS the L3
  packet - per the reference. Upper-layer retransmits will retry.
- `demote_packet_to_layer3` - originate path used by the `ping`
  CLI. Builds an IP header (src = loopback if configured),
  prepends it to the user payload, looks up the route, and feeds
  directly into the push-down. Bypasses the local-delivery check
  so a packet addressed to ourselves still goes out the wire.
- `is_layer3_local_delivery` matches dst against the loopback and
  every L3-mode interface IP on the node.
- `promote_pkt_to_layer4` is a printing stub - ch10 will lower
  ping/traceroute handlers into it.
- L2 (`layer2_frame_recv`) gained an `IP_HDR_TYPE` dispatch case
  that strips the Ethernet (or VLAN+Eth) header before calling
  the new L3 entry point.
- CLI: `run node <name> ping <ip>` originates an IP packet with
  payload `ping`.

## LPM byte-order fix

ch8's doc flagged this. The reference's lookup did
`inet_ntop(AF_INET, &dest_ip, ...)` on a *host*-order `dest_ip`
which printed the dotted-quad with the bytes reversed and never
matched anything. Fix is one line:

```c
unsigned int net_order_ip = htonl(dest_ip);
inet_ntop(AF_INET, &net_order_ip, dest_ip_str, 16);
```

Without this the entire forwarding pipeline is dead - no route
ever matches, every packet drops with "no route". Confirmed via
the smoke test on the first run before the fix landed.

## IpHdr size gotcha

The header struct in `Layer3/layer3.h` uses `short` for
`ttl`/`protocol`/`checksum` (matching how the reference's PDF
describes it). Combined with `#pragma pack(1)` that makes
`sizeof(IpHdr) == 22` bytes, not 20. `ihl = 5` says the header is
`5 * 4 = 20` bytes, so naive `memcpy(buf + ihl*4, payload, ...)`
on originate writes the payload's first 2 bytes ON TOP of
`dst_ip`. We hit this immediately - `dst_ip` came out as
`105.112.1.2` (ASCII `i`, `p`, ...) and LPM legitimately found
no route.

Workaround: use `sizeof(IpHdr)` for both the originator's payload
offset AND the receiver's L4 chop. Both sides agree, the wire
total_length reflects 22 + payload, and the LPM lookup sees the
correct dst.

A "proper" fix would be to change ttl/protocol/checksum to `char`
each, taking the struct to a real 20 bytes. Left as-is to stay
faithful to the book; documented here.

## ARP-miss policy

Drop the packet, fire ARP, return. No queue, no retry. This is
the reference's behavior and is fine for the tests we care about:
either pre-resolve ARP via `run node X resolve-arp <ip>` first,
or accept that the first ping seeds the cache and a second one
delivers. ch10's ping loop will get this right "for free" because
it sends multiple packets.

## Bypass of local-delivery in the originate path

`demote_packet_to_layer3` deliberately does NOT call
`layer3_pkt_recv_from_layer2`. If it did, a packet whose dst
happens to be one of our own IPs (legal use case - e.g. pinging
our own loopback) would be intercepted by
`is_layer3_local_delivery` and short-circuited to L4 with no L2
round-trip. We want originate to mean "put this on the wire" so
we duplicate the LPM + push-down logic. Small code, no
ambiguity.

## End-to-end demo

```
samtcpip> run node R0_re resolve-arp 20.1.1.2
process_arp_broadcast_request : ARP Broadcast msg recvd on interface eth0/1 of node R1_re
process_arp_reply_msg : ARP reply msg recvd on interface eth0/0 of node R0_re
samtcpip> run node R0_re ping 20.1.1.2
L4 Packet received : node R1_re : iif eth0/1 : proto 2048 : size 5 : payload `ping`
```
