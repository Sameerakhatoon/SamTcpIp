# ch30 - source IP via route lookup (shared helper)

UDP (ch13) and TCP (ch22) each shipped a near-identical inline
`pick_src_ip` that only did subnet-match. ch30 promotes the
algorithm to `node_pick_src_ip` in Layer3 and adds LPM-route
support so curl OUT to a non-connected destination picks the
correct egress interface IP, not the loopback.

## Algorithm

Four steps in priority order:

1. **LPM lookup**. If a matching route has an explicit `oif`
   (non-direct), use that interface's IP.
2. **Subnet-match** on `dst_ip` for directly-connected
   destinations.
3. **Loopback fallback** if the node has one.
4. Return 0.

## What landed

- `Layer3/layer3.{h,c}` ships `node_pick_src_ip(node, dst_ip_host)`.
- `Layer4/tcp.c::tcp_pick_src_ip` and `Layer4/udp.c::udp_pick_src_ip`
  reduce to one-line wrappers.
- New CLI `show node X pick-src <dst-ip>` reports what the
  algorithm chooses for a given destination - useful both for
  test assertion and for ops debugging.

## End-to-end demo

```
samtcpip> show node R0_re pick-src 20.1.1.2          ; directly-connected
pick-src : R0_re : dst=20.1.1.2 -> src=20.1.1.1

samtcpip> show node R0_re pick-src 30.1.1.2          ; no route -> loopback
pick-src : R0_re : dst=30.1.1.2 -> src=122.1.1.0

samtcpip> config node R0_re route 30.1.1.0 24 20.1.1.2 eth0/0
samtcpip> show node R0_re pick-src 30.1.1.2          ; LPM hits oif
pick-src : R0_re : dst=30.1.1.2 -> src=20.1.1.1
```

The transition from loopback to OIF-IP when a route is installed
is the headline. Curl OUT now picks the right src.

## Design choices

### Why LPM before subnet-match

Subnet-match is a special case of LPM (the direct route IS the
subnet-match). LPM is the correct lookup; we keep subnet-match
as a fallback ONLY for the "no route at all" case, which on a
fresh node is more permissive than strictly correct - but
matches the simulator's existing behavior.

A future refactor could drop step 2 since auto-direct routes
make step 1 always hit for directly-connected dst.

### Why we don't pre-prune the LPM result by `is_direct`

A direct route can carry a `gw_ip` of zero. Without the
`is_direct` check, we'd try to look up an iface named by an
empty `oif`. We skip those and fall through to subnet-match.

### Why no caching

`l3rib_lookup_lpm` is O(N) in the route count today. Caching the
result per (dst, generation) would speed up repeated calls.
N is small (under 10 routes per node); not on the curl needle.

## What's NOT here

- IPv6 source selection.
- Per-flow source-IP pinning.
- Sticky source selection for long-lived TCBs (we re-pick on
  every send).
- RFC 6724 full source-address-selection rules.

## Test discipline

| Axis             | Positive                                                            | Negative                                              |
|------------------|---------------------------------------------------------------------|-------------------------------------------------------|
| Subnet-match     | `pick-src : R0_re : dst=20.1.1.2 -> src=20.1.1.1`                   | -                                                     |
| Loopback fall    | `pick-src : R0_re : dst=30.1.1.2 -> src=122.1.1.0`                  | -                                                     |
| LPM override     | After route install, src=20.1.1.1 (not 122.1.1.0)                   | -                                                     |
| Ping/UDP/TCP     | All still work via the promoted helper                              | -                                                     |

## What's left

ch31 onwards: default route handling (0.0.0.0/0 in LPM),
ephemeral port allocation, TCP active-open polishing, ICMP error
receive, then DHCP client + DNS client + the Milestone 3 goal
(curl OUT works).
