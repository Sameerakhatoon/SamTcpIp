# ch6 - L2 MAC-based switching

A Node operating as an L2 switch now learns source MACs into a
per-Node `MacTable` and forwards frames by MAC table lookup
(flooding when the table miss happens or when the dst is the
broadcast MAC). ARP requests pass through transparently so two
hosts on the same subnet can resolve each other across the switch.

End-to-end:

```
$ printf 'run node H1 resolve-arp 10.1.1.2\nshow node L2SW mac\nshow node H1 arp\nquit\n' \
    | ./testapp --topo l2switch
process_arp_broadcast_request : ARP Broadcast msg recvd on interface eth0/6 of node H2
process_arp_broadcast_request : ARP Broadcast msg recvd on interface eth0/1 of node H4
H4 : ARP Broadcast req msg dropped, Dst IP address did not match
process_arp_reply_msg : ARP reply msg recvd on interface eth0/4 of node H1
    MAC : 146:138:215:162:0:0   | Intf : eth0/7   <- H2's MAC, learned from the reply
    MAC : 62:34:140:249:0:0     | Intf : eth0/5   <- H1's MAC, learned from the broadcast
IP : 10.1.1.2, MAC : 146:138:215:162:0:0, OIF = eth0/4
```

## L2 vs L3 mode on an Interface

`IntfL2Mode` now lives on every Interface:

- `L2_MODE_UNKNOWN`: not configured. ch6 L2 gate drops frames.
- `ACCESS`: belongs to (at most) one VLAN.
- `TRUNK`: belongs to many VLANs.

An Interface is in **L3 mode** iff `is_ipadd_config == true`. ACCESS
/ TRUNK are mutually exclusive with L3 mode. Flipping L3 -> L2 via
`interface_set_l2_mode` stashes the prior `is_ipadd_config` flag in
`is_ipadd_config_backup` so it can be brought back later (ch7
groundwork).

New macros: `IF_L2_MODE(intf)`, `IS_INTF_L3_MODE(intf)`.

## Rewritten L2 acceptance gate

`l2_frame_recv_qualify_on_interface(intf, eth)`:

- Neither L2 nor L3 configured -> drop.
- L2 (ACCESS or TRUNK) -> accept (the L2 switch does MAC filtering
  itself, with VLAN gating coming in ch7).
- L3 -> accept only if `dst_mac == IF_MAC(intf)` OR is the
  broadcast MAC.

The ch4 test had to be loosened to "L2 Frame" (either Accepted or
Rejected) because raw text payloads no longer pass the gate.

## MacTable

Per-Node, hung off `NodeNwProp.mac_table` as an opaque pointer (the
full struct lives in `Layer2/layer2.h`). Entries are
`MacTableEntry { mac, oif_name, mac_entry_glue }` chained via the
glthread. CRUD mirrors the ARP table:

- `init_mac_table`, `mac_table_lookup`, `clear_mac_table`,
  `delete_mac_table_entry`, `mac_table_entry_add`, `dump_mac_table`.
- Entries are keyed by 6-byte MAC. Equality via
  `IS_MAC_TABLE_ENTRY_EQUAL` (MAC + OIF) - keeps the same row alive
  on repeat learning, but moves it when the source moves ports.

## Learning + forwarding

`l2_switch_recv_frame(iif, pkt, size)` is what `layer2_frame_recv`
calls when the receiving interface is in L2 mode.

`l2_switch_perform_mac_learning(node, src_mac, if_name)`:

- Allocate a new `MacTableEntry`, stamp `(src_mac, iif_name)`,
  call `mac_table_entry_add`. Free the duplicate when it's
  already-known.

`l2_switch_forward_frame(node, recv_intf, pkt, size)`:

- Broadcast dst -> `send_pkt_flood` (skipping `recv_intf`).
- Known unicast -> `send_pkt_out` via the learned OIF.
- Unknown unicast -> `send_pkt_flood` (skipping `recv_intf`).

## `send_pkt_flood` gained an exempted-intf parameter

```
int send_pkt_flood(Node*, Interface* exempted_intf, char* pkt, size_t sz);
```

Without this the switch would echo the broadcast right back onto
the port it arrived on. NULL skips no interface (still useful for
hosts that flood out everywhere).

## Bug fix on arp_table_entry_add

Old code memcmp'd whole `ArpEntry` structs to decide "already
present". That includes the embedded `GlThread` links - so two
otherwise-identical entries that happen to be on different list
positions compare unequal. Replaced with `IS_ARP_ENTRIES_EQUAL`
macro (IP + MAC + OIF only).

## CLI growth

- `show node <name> mac` - dump the per-Node mac-learning table.
- `config node <name> interface <if> l2mode <access|trunk>` - set
  an interface into ACCESS or TRUNK mode at runtime.

testapp got a `--topo l2switch` flag so the ch6 test can pick the
new `build_simple_l2_switch_topo()` while ch1..ch5 stick with the
default 3-node ring.

## Source quirk preserved

`node_set_intf_vlan_membsership` - "membsership" typo carried over
from the source verbatim per project rules. ch7's full VLAN code
keeps using this name.

## Test

`tests/06-l2-switching.sh` runs the canonical scenario through the
REPL on the L2-switch topology:

1. H1 fires `resolve-arp 10.1.1.2`.
2. Switch floods the broadcast; H2 + H4 both receive.
3. H4 drops (its IP is 10.1.1.4, not 10.1.1.2).
4. H2 replies; switch forwards by mac-table lookup back to H1's port.
5. Assert: L2SW's mac table has entries on both `eth0/5` (H1) and
   `eth0/7` (H2); H1's ARP cache holds 10.1.1.2 with OIF = `eth0/4`.
