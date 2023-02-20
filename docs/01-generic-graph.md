# ch1 - generic graph + glthread

Lays down the substrate everything else sits on: a generic in-memory
graph (Nodes, Links, Interfaces) and a tiny intrusive doubly-linked
list (`GlThread`) used for every "X has many Y" relationship in the
project.

## Why a generic graph first

Real network topologies (a router, two L2 switches, a host hanging
off each) are just graphs with extra labels on the vertices and
edges. Modelling that first - before we know what a "MAC address" or
"interface mode" is - keeps the data structures small and the
domain payload (MACs, IPs, VLANs, ARP / mac tables) cleanly bolted
on top in later chapters via per-Node and per-Interface "nw_props"
structs.

## Glue thread

`GlThread { left, right }` is embedded directly inside any struct
that needs to live on a list. Two reasons:

- One struct, many lists. A `Node` later sits on the topology's
  node_list AND on whatever transient walk a routing algorithm
  spins up - no second allocation.
- Cache locality. Iteration reads the owning struct's own bytes
  rather than chasing pointer-to-pointer.

The recovery is `GLTHREAD_TO_STRUCT(fn, T, field)`: given a
`GlThread*` known to be embedded inside a `T`, subtract the byte
offset of `field` within `T` and you have the `T*`. The macro
expands to a `static inline` so each user gets their own typed
accessor (`graph_glue_to_node` etc).

Iteration uses `ITERATE_GLTHREAD_BEGIN / END`, which caches `right`
into a scratch var so a `remove_glthread(cur)` inside the loop body
does not blow the walk up.

## Graph shape

```
Graph
  topology_name[32]
  node_list (GlThread head)
    -> Node R0
         intf[0..MAX_INTF_PER_NODE-1]
         graph_glue
    -> Node R1
    -> ...

Link
  intf1 (Interface)   <- both Interfaces live INSIDE the Link
  intf2 (Interface)      so freeing the Link frees both ends
  cost
```

A `Link` owns its two `Interface`s by value. A `Node` only stores
pointers to Interfaces - it does not own them, the Link does. The
`get_nbr_node(intf)` helper exploits the address: whichever
`Interface*` we hold, the OTHER address inside the Link is the peer.

## Test

`tests/01-graph-build.sh` builds the canonical 3-node ring, runs
`dump_graph`, and asserts every Node + every link cost line appears
in the output.

## What ch2 needs from this

- `Node` and `Interface` reserve room for `node_nw_prop` and
  `intf_nw_props` payloads (added in ch2 via additional fields, not
  by editing the graph layer's logic).
- `GlThread` already covers the ARP table, mac table, and per-Node
  routing-table lists that ch5+ will need.
