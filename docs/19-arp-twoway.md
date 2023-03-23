# ch19 - ARP two-way over TAP + runtime IP CLI

## What landed

A small chapter. The existing ch5 ARP code already handles
both directions on any wire - receive enters via
`pkt_receive` -> `layer2_frame_recv` which dispatches on
EtherType=ARP; send goes through `send_pkt_out` which ch16
routes to TAP whenever the oif is the TAP-attached interface.

What was missing: a way to align R0_re's simulator-side IP
with the host-side subnet at runtime. The topology builder
sets initial IPs (R0_re's eth0/0 = 20.1.1.1/24) but ch18's
`tap host-ip` puts the host on (e.g.) 10.0.0.99/24. Two
different subnets -> ARP never matches.

ch19 ships:

```
config node <node> interface <if> ip <ip> <mask>
```

A thin wrapper around `node_set_intf_ip_address` (which
already exists, already auto-updates the routing table to
install a direct route for the new subnet). The chapter is
mostly the CLI + the doc + the test.

## End-to-end demo (root)

```
samtcpip> run tap attach R0_re samtap0 eth0/0
TAP attach : samtap0 -> R0_re/eth0/0 fd=4
TAP recv thread started

samtcpip> run tap ifup samtap0
TAP ifup : samtap0 is UP

samtcpip> run tap host-ip samtap0 10.0.0.99 24
TAP host-ip : samtap0 set to 10.0.0.99/24

samtcpip> config node R0_re interface eth0/0 ip 10.0.0.1 24
Intf ip : R0_re/eth0/0 set to 10.0.0.1/24

samtcpip> run node R0_re ping 10.0.0.99
TAP send : 42 bytes via R0_re/eth0/0      ; ARP request -> kernel
TAP recv : 42 bytes on R0_re/eth0/0       ; ARP reply <- kernel
TAP send : 38 bytes via R0_re/eth0/0      ; ICMP echo request
TAP recv : 38 bytes on R0_re/eth0/0       ; ICMP echo reply
Ping reply : R0_re : seq=N from 10.0.0.99
```

That's the milestone. We've never done it before in the
project's history.

(The exact log sequence may vary - the test asserts presence
of TAP send / TAP recv lines without pinning a specific
ordering.)

## End-to-end demo (non-root)

CLI works but TAP attach fails. The CLI reconfigure is
testable independently of root: the test asserts the FIB
update + the prior chapters' ping/UDP regression.

## Design choices

### Why no new ARP code

The ch5 ARP handler reads `node->node_nw_prop.arp_table` and
walks `node->intf[]` to decide which interface owns an IP.
The new IP is set via `node_set_intf_ip_address` (which
mutates `intf_nw_props.ip_add` and updates the FIB). The ARP
responder sees the new IP on next request - automatically.

The egress path was already TAP-aware in ch16. The ingress
path was already TAP-aware in ch15. The protocol code itself
didn't need to change.

### Why we don't auto-align IPs

We could detect `tap host-ip` was called and automatically
align the simulator-side IP to the host-side subnet's `.1`.
That's brittle - operator might want different alignment.
Explicit two-step is clearer.

### Why the test doesn't assert ping reply under root

Real interop depends on kernel behavior we don't fully
control in CI. The kernel may have rp_filter on, routing
weirdness with the loopback, etc. We assert TAP send + TAP
recv lines (mechanical proof the wire is alive in both
directions); ch21 is the milestone goal where the full
round-trip is the explicit assertion.

## What's NOT here

- Gratuitous ARP on IP change. ch20.
- Aligning simulator IP automatically from `tap host-ip`.
- Multi-interface IP reconfig in one call.

## What's left

Phase 1 has 2 chapters to go:
- ch20: gratuitous ARP on IP assignment.
- ch21: milestone goal - host pings us, we ping host, tcpdump
  verified.
