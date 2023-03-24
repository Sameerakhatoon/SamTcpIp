# ch20 - gratuitous ARP on IP assignment

## What landed

`send_gratuitous_arp(node, oif)` in `Layer2/layer2.c`: builds
a broadcast ARP REPLY with `src_ip == dst_ip == oif's IP` and
target MAC = `ff:ff:ff:ff:ff:ff`. Peers (including the Linux
kernel on the TAP side) see a "free" reply and update their
ARP caches through the existing
`arp_table_update_from_arp_reply` path - no new ingress
dispatch needed.

Hooks:
- `config node X interface <if> ip <ip> <mask>` fires GARP
  after the IP set succeeds.
- New `run node X arp-announce` iterates over every L3 mode
  interface and emits one. Manual trigger for tests + ops.

## End-to-end demo

```
samtcpip> run node R0_re arp-announce
GARP : R0_re : announcing 20.1.1.1 on eth0/0
GARP : R0_re : announcing 40.1.1.1 on eth0/4
GARP : R0_re : announced on 2 interface(s)

samtcpip> config node R0_re interface eth0/0 ip 10.0.0.1 24
Intf ip : R0_re/eth0/0 set to 10.0.0.1/24
GARP : R0_re : announcing 10.0.0.1 on eth0/0
```

Under root with TAP attached, the GARP goes out the TAP
(through `send_pkt_out` -> ch16's TAP branch) and reaches the
host kernel.

## Design choices

### Why an ARP REPLY (not REQUEST)

RFC 5227 sec 2.3 specifies the announcement as a REPLY. Some
older stacks ignore unsolicited REQUESTs. REPLY is the
universally-accepted form.

### Why broadcast dst MAC

Broadcast guarantees every peer on the segment sees it. The
RFC explicitly says broadcast.

### Why we fire on every IP set

Including the initial one set by the topology builder? No -
the topology builder bypasses the CLI handler. Only the
runtime `config interface ip` path fires it. The first IP
the simulator boots with does NOT get a GARP today.

That's the correct behaviour for our scope: at boot time
there's no TAP attached yet, so no kernel peer to announce
to. Once an operator brings up the TAP and aligns the IP via
the CLI, the GARP follows.

### Why we don't ARP-probe before announcing

RFC 5227 actually specifies: probe FIRST (check no one else
owns the IP), THEN announce. We skip the probe because:
- The host kernel will ignore an announce for an IP it
  doesn't claim - no harm.
- Probe + wait adds 2 seconds to every IP set, awkward for
  tests.
- A future "conflict detection" chapter can layer probe on
  top.

## What's NOT here

- ARP probe before announce (RFC 5227 sec 2.1).
- Repeat-announce timer (RFC 5227 says multiple announces
  spaced 2 seconds apart).
- Conflict detection on incoming ARPs.

## Test discipline

| Axis             | Positive                                            | Negative                                              |
|------------------|-----------------------------------------------------|-------------------------------------------------------|
| Manual announce  | `GARP : R0_re : announcing 20.1.1.1 on eth0/0`      | -                                                     |
| Manual announce  | `GARP : R0_re : announced on 2 interface(s)`        | -                                                     |
| IP set fires GARP| `GARP : R0_re : announcing 10.0.0.1 on eth0/0`      | -                                                     |
| Root: TAP egress | `TAP send :` (>=1 line, root only)                  | -                                                     |
| Ping regression  | `Ping reply : R0_re : seq=3 from 20.1.1.2`          | -                                                     |

## What's left

ch21 - Milestone 1 goal: host pings us at our IP, we ping
host, tcpdump-verified round-trip.
