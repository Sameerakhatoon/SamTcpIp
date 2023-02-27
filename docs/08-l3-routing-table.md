# ch8 - L3 routing table

## What landed

- `RtTable` opaque pointer on every `NodeNwProp` (alongside the ARP
  and MAC tables from ch5/ch6). Forward-declared in `net.h`; full
  type lives in `Layer3/layer3.h`.
- `L3Route { dest[16], mask, is_direct, gw_ip[16], oif[IF_NAME_SIZE],
  rt_glue }` - one row of the routing table.
- CRUD: `init_rt_table`, `rt_table_lookup` (exact match by
  dest+mask), `rt_table_add_route`, `rt_table_add_direct_route`,
  `delete_rt_table_entry`, `clear_rt_table`, `dump_rt_table`.
- `l3rib_lookup_lpm` - longest-prefix-match lookup with a
  `0.0.0.0/0` default-route fallback. ch9 will use this.
- Auto-install hook from net.c: configuring an interface IP or
  loopback now drops the matching directly-connected route into
  the Node's `RtTable` automatically.
- CLI:
  - `show node <name> route` dumps the table.
  - `config node <name> route <prefix> <mask> <gw> <oif>` installs
    a static route. Use `direct` as the gateway token (and `-` as
    a placeholder for oif) to install a direct route via the CLI.
- `IpHdr` struct (packed) sitting in `Layer3/layer3.h` ready for
  ch9's forwarding pipeline.

## Rationale

The reference repo introduces routing as a feature long before
forwarding actually uses it. We do the same so we can:

1. exercise the table data structure on its own (LPM, replace,
   delete, dump) with a clean E2E test, and
2. have direct routes already present when ch9 wires the
   `layer3_pkt_recv` -> next-hop -> ARP -> L2 chain.

Auto-installing direct routes when an IP is set means callers
never have to think about routing for the simple case of "host
talks to peer on the same subnet". The L3 forwarding code in ch9
can then assume the table is always populated.

## Gotchas (worth documenting)

### Mask byte-order in the reference's LPM lookup

The reference does:

```c
inet_pton(AF_INET, str, &dst_int);   // network byte order
dst_int = htonl(dst_int);            // host byte order
l3rib_lookup_lpm(rt_table, dst_int);
```

and then inside the lookup:

```c
inet_ntop(AF_INET, &dest_ip, dest_ip_str, 16); // expects NETWORK order
```

Because `dst_int` is in host order at that point, `inet_ntop`
prints the dotted-quad with the bytes flipped (e.g. `50.50.50.0`
becomes `0.50.50.50`). The LPM walk then can't match anything.

We preserve the behavior to stay faithful to the reference, but
that means LPM cannot be used as a duplicate-detection fast path
on insert. So `rt_table_add_route` skips the LPM check entirely
and relies on `_rt_table_entry_add`'s exact (dest+mask)
`rt_table_lookup`, which works regardless of byte order. Adding
the same route twice is a silent no-op; no error is printed.

ch9 will need a real fix - probably keeping `dst_int` in network
byte order all the way through and dropping the `htonl`. Noting
it here so we remember.

### Replace-or-insert semantics

If you install a route with the same (dest, mask) as an existing
row but different gw/oif/is_direct, the old row is removed and
the new one inserted. This is what lets `config node ... route`
overwrite an auto-installed direct route with a static one
without the user having to delete first.

### Direct routes through the CLI

`config node X route 50.50.50.0 24 direct -` parses `direct` as
the gateway sentinel and passes `gw=NULL, oif=NULL` to
`rt_table_add_route`, which sets `is_direct = true` and leaves
the gw/oif slots empty. The `-` is just a placeholder to satisfy
the 5-level command grammar.
