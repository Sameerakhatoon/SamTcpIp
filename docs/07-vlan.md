# ch7 - VLAN support (802.1Q tagging, ingress / egress decisions)

The L2 switch becomes VLAN-aware. Frames that arrive on an ACCESS
port get tagged on ingress; frames that leave on an ACCESS port
get untagged on egress. TRUNK ports preserve tags. A broadcast in
vlan X only floods to ports in vlan X.

End-to-end:

```
$ printf 'run node H1 resolve-arp 10.1.1.2\nshow node H1 arp\nquit\n' \
    | ./testapp --topo vlan
ARP Broadcast msg recvd on interface eth0/6 of node H2     # H2 in vlan 10 - reached
ARP reply msg recvd on interface eth0/4 of node H1
IP : 10.1.1.2, MAC : ..., OIF = eth0/4

$ printf 'run node H1 resolve-arp 10.1.1.3\nshow node H1 arp\nquit\n' \
    | ./testapp --topo vlan
ARP Broadcast msg recvd on interface eth0/6 of node H2     # H2 still sees it (vlan10)
H2 : ARP Broadcast req msg dropped, Dst IP address did not match
                                                            # H3 (vlan 20) never sees the broadcast
                                                            # H1's ARP cache stays empty
```

## On-wire structs

`Vlan8021qHdr` is 4 bytes, packed:

```
tpid (16)  | tci_pcp (3) | tci_dei (1) | tci_vid (12)
```

`VlanEthernetHdr` splices the tag between `src_mac` and `type`:

```
dst_mac (6) | src_mac (6) | vlan_8021q_hdr (4) | type (2) | payload | FCS
```

So an untagged frame is `EthernetHdr`; a tagged frame is layout-
compatible up through `src_mac`, then a 4-byte tag, then the rest.

## Detecting tagged frames

Bytes 13..14 of any frame are either the ether-type (untagged) or
the tpid 0x8100 (tagged). `is_pkt_vlan_tagged(eth)` casts those two
bytes as `Vlan8021qHdr*` and returns it iff tpid matches. The
payload accessor `GET_ETHERNET_HDR_PAYLOAD(eth)` then picks the
correct offset for ARP / L3 dispatch on whichever flavour came in.

## In-place tag + untag

`tag_pkt_with_vlan_id(eth, total_pkt_size, vlan_id)`:

- If already tagged: overwrite tci_vid; size unchanged.
- Otherwise snapshot the frame into a temp buffer, write the tag
  into the gap between src_mac and type, then copy the (type +
  payload + FCS) tail forward by 4 bytes. Returns `total + 4`.

`untag_pkt_with_vlan_id(eth, total_pkt_size)` is the inverse. The
caller must ensure the buffer has 4 bytes of headroom (our send /
recv buffers are 2 KB so the splice is always safe).

## L2 acceptance gate (frame ingress)

`l2_frame_recv_qualify_on_interface(intf, eth, &vlan_id_out)` now
covers the full case matrix:

| recv mode  | tag    | port VLAN  | action            |
| ---------- | ------ | ---------- | ----------------- |
| neither    | -      | -          | drop              |
| ACCESS     | no     | unset      | accept            |
| ACCESS     | yes    | unset      | drop              |
| ACCESS     | yes X  | yes Y      | accept iff X == Y |
| ACCESS     | no     | yes Y      | accept + tag Y    |
| TRUNK      | no     | -          | drop              |
| TRUNK      | yes X  | members Y  | accept iff X in Y |
| L3         | yes    | -          | drop              |
| L3         | no     | -          | dst MAC match     |

When the table dictates "tag and accept" (untagged ingress on an
ACCESS port that has a VLAN), the qualifier writes `vlan_id_out`;
`layer2_frame_recv` then calls `tag_pkt_with_vlan_id` in place
before handing off to the L2 switch.

## Per-port egress (frame egress)

`l2_switch_send_pkt_out(pkt, size, oif)` enforces VLAN rules at
each output interface:

- ACCESS port + no VLAN + untagged    -> forward
- ACCESS port + has VLAN + untagged   -> drop
- ACCESS port + has VLAN X + tag == X -> **UNTAG** and forward
- ACCESS port + has VLAN X + tag != X -> drop
- TRUNK port + tag in members         -> forward as-is
- TRUNK port + untagged               -> drop

Deviation from the upstream code: the original reference forwards
tagged on ACCESS egress, which would leave a tagged frame arriving
at an L3 host (the L3 qualifier then drops tagged frames). We
untag on ACCESS egress so the host receives a plain frame, which
is what real switches do. This is what makes end-to-end ARP
through an access port actually work.

## VLAN-aware flood

`l2_switch_flood_pkt_out(node, exempted_intf, pkt, size)` walks
every port (skipping the recv port) and lets `l2_switch_send_pkt_out`
filter by VLAN per port. A broadcast tagged vlan10 will only land
on ports in vlan 10.

## VLAN membership management

`node_set_intf_vlan_membsership(node, if_name, vlan_id)` typo
preserved. Real behaviour now:

- ACCESS: store in vlans[0]. Re-calling overwrites.
- TRUNK : append to the first free slot. No-op if already a
  member; "max membership reached" on overflow.

Two helpers used by both the qualifier and the egress code:

- `get_access_intf_operating_vlan_id(intf)` returns vlans[0]
  (asserts ACCESS).
- `is_trunk_interface_vlan_enabled(intf, vlan_id)` scans the slots
  (asserts TRUNK).

## Test topology + driver

`build_vlan_l2_switch_topo()` wires three L3 hosts into one switch:
H1 + H2 share vlan 10, H3 sits alone in vlan 20. All three hosts
share the 10.1.1.0/24 subnet IP-wise. `--topo vlan` on testapp
selects it.

## Test

`tests/07-vlan.sh` covers both directions:

1. `run node H1 resolve-arp 10.1.1.2` (same vlan)
   - H2 sees the broadcast, replies; H1's ARP cache holds 10.1.1.2.
2. `run node H1 resolve-arp 10.1.1.3` (cross vlan)
   - Negative assertion: H3 must NOT appear in the receive logs.
   - Negative assertion: no ARP reply lands on H1.
   - Positive assertion: H2 still gets the broadcast (vlan10 flood
     reaches it) but drops it on dst-IP mismatch.

So the same access switch ports broadcast the request to the
correct vlan only, and isolation holds at L2.
