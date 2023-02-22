# ch2 - network topology (node + interface properties)

Layers MAC / IP / loopback / device-type onto the ch1 graph. The
graph layer stays domain-blind: networking lives entirely in
`net.h` / `net.c` and reaches into Node / Interface via two
embedded payload structs.

## Why payload structs

`Node` and `Interface` each get one new field:

```
struct Node      { ...; NodeNwProp  node_nw_prop;  };
struct Interface { ...; IntfNwProps intf_nw_props; };
```

Embedded by value (not pointer) so a Node / Interface is still a
single allocation. The structs live in `net.h` and the graph layer
just composes them by inclusion. Net-aware functions
(`node_set_*`, `dump_nw_graph`) live alongside the payload defs.

## Include direction

`graph.h` includes `net.h`, not the other way round, because the
payload layouts (`NodeNwProp`, `IntfNwProps`) need to be known to
the compiler before it can `sizeof(Node)`. `net.h` forward-declares
`Node` / `Interface` / `Graph` so its function signatures compile
without pulling in the full graph layout.

## Types added

- `IpAddr { char ip_addr[16]; }` - dotted-quad string slot.
- `MacAddr { char mac[48]; }` - 48-byte buffer (the source material
  uses 48 not 6; preserved verbatim, the MAC formatting only reads
  the first 6 bytes).
- `NodeNwProp { flags, is_lb_addr_config, lb_addr }`.
- `IntfNwProps { mac_add, is_ipadd_config, ip_add, mask }`.

## Device-type flags

`L3_ROUTER`, `L2_SWITCH`, `HUB` are bit values (already shifted), so
`node->node_nw_prop.flags |= L3_ROUTER` is the direct OR. A Node can
carry more than one (router-bridge) - `IS_BIT_SET` from the macro
set tests by bit position; the device-type macros use shifted
values, so `flags & FLAG` is the right test (`node_set_loopback_address`
uses the direct mask).

## MAC heuristic

`interface_assign_mac_address` writes the owning node + interface
names into the MAC byte buffer. Not a real OUI / hex address - just
something unique per (node, intf) pair so debug output is
recognisable. The first byte of every R0_re interface MAC is `R`
(ASCII 82) by construction; the test asserts that as a sanity check.

## Lookup macros

`IF_MAC(intf)` / `IF_IP(intf)` / `NODE_LO_ADDR(node)` are inline
accessors so callers do not have to type the long member-path
chain. They expand to the embedded buffer directly so they can be
used as `strcpy` / `printf` targets.

## Setter contract

- `node_set_device_type` is a plain OR onto `flags`.
- `node_set_loopback_address` asserts that the Node has
  `L3_ROUTER` set first and is not a `HUB`. Loopback only makes
  sense on a routing node.
- `node_set_intf_ip_address` requires the interface name to exist;
  copies the dotted-quad into the slot and sets `mask` +
  `is_ipadd_config = true`. An interface with
  `is_ipadd_config` set IS in L3 mode.
- `node_unset_intf_ip_address` zeroes the slot and clears the flag.

## Test

`tests/02-network-props.sh` runs `./testapp`, which now calls
`dump_nw_graph` instead of the ch1 bare `dump_graph`, and grep-
asserts: the topology header, the three loopbacks (`122.1.1.0..2`),
all six interface IP lines, and the deterministic MAC sentinel
byte.
