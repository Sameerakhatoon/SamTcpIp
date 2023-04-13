# ch32 - ephemeral port allocation + tcp_connect

`tcp_send_syn` (ch22) used a fixed src_port (33333) for test
determinism. Real outbound TCP needs unique source ports per
connection so the 4-tuple is unique.

## What landed

- `tcp_alloc_ephemeral_port(node, local_ip, remote_ip,
  remote_port)`: walks existing TCBs in the Linux range
  32768-60999. Returns the first port that doesn't collide on
  the 4-tuple. Round-robin via a static `next` counter that
  wraps.
- `tcp_connect(node, dst_ip_host, dst_port)`: real active-open
  API. Calls `node_pick_src_ip` -> ephemeral allocator ->
  `tcp_send_syn`. Returns the chosen local port (or 0 on
  failure).
- CLI: `run node X tcp-connect <ip> <dport>`.

## End-to-end demo

```
samtcpip> config node R1_re tcp-listen 80
samtcpip> run node R0_re ping 20.1.1.2          ; warm ARP

samtcpip> run node R0_re tcp-connect 20.1.1.2 80
TCP connect : R0_re : src=20.1.1.1:32768 -> dst=20.1.1.2:80
TCP send : R0_re : SYN seq=8192 to 20.1.1.2:80
... handshake completes, both sides ESTABLISHED

samtcpip> run node R0_re tcp-connect 20.1.1.2 80
TCP connect : R0_re : src=20.1.1.1:32769 -> dst=20.1.1.2:80
... second connection, distinct source port

samtcpip> show node R0_re tcp
  [0] state=ESTABLISHED local=32768 remote=20.1.1.2:80
  [1] state=ESTABLISHED local=32769 remote=20.1.1.2:80
```

Two concurrent connections to the same `(dst, dport)` peacefully
share the wire. Real curl OUT with parallel HTTP requests would
look exactly like this.

## Design choices

### Why 32768-60999

Linux's `/proc/sys/net/ipv4/ip_local_port_range` default. Other
OSes vary. Hardcoded; could be a sysctl-equivalent later.

### Why a static `next` counter

Round-robin across the range avoids hot-spotting the low end.
Collisions are rare (we cap at 2 connections in tests); a real
high-PPS stack would want a proper allocator with a bitmap.

### Why allow port reuse on different 4-tuples

The same local port can be in multiple TCBs as long as their
remote 4-tuples differ. This matches Linux + RFC 793.

`tcb_find` accepts the 4-tuple so the recv path correctly
dispatches even when two connections share a local port. The
allocator only filters by 4-tuple, not by local port alone.

### Why tcp_send_syn stays

ch22 tests assert specific seq numbers + 4-tuples. Keeping the
fixed-port API lets those tests stay deterministic. New tests
use `tcp_connect` for realism.

## What's NOT here

- Privileged ports (under 1024) for any-port-binding apps.
- SO_REUSEADDR / SO_REUSEPORT semantics.
- Per-Node sysctl knob for the range.
- Bitmap allocator for performance.

## Test discipline

| Axis              | Positive                                                       |
|-------------------|----------------------------------------------------------------|
| First connect     | `src=20.1.1.1:32768 -> dst=20.1.1.2:80`                        |
| Second connect    | `src=20.1.1.1:32769 -> dst=20.1.1.2:80`                        |
| Both establish    | 2x `SYN-ACK ... -> ESTABLISHED` on R0                          |
| TCB list shows 2  | `state=ESTABLISHED local=32768/32769 remote=20.1.1.2:80`       |
| Legacy fix-port   | `tcp-syn` still works at fixed src_port for ch22 tests         |

## What's left

ch33: ICMP error receive. When our outbound TCP connect hits a
dead host, the router sends back ICMP Dest Unreach. Our recv
path should pull the embedded TCP ports out + abort the
pending TCB.

Then DHCP client, DNS client, and the Milestone 3 goal.
