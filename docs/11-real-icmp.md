# ch11 - real ICMP

First chapter past the book. Replaces ch10's homegrown
`PING_PROTO=201 + PingMsg` with the real RFC 792 ICMP wire format
and an RFC 1071 Internet checksum. The user-facing `run node X
ping <ip>` CLI is unchanged; under the hood the protocol number,
header layout, and integrity check are now real.

## What landed

### Layer3/icmp.{h,c}

- Packed `IcmpHdr { type, code, checksum, identifier, sequence }`.
- `icmp_checksum(buf, len)` per RFC 1071: 16-bit ones-complement
  sum read as big-endian words, carry folded, complement returned.
- Constants `ICMP_PROTO=1` (IANA), `ICMP_ECHO_REQUEST=8`,
  `ICMP_ECHO_REPLY=0`. Nothing else - per PLAN.md rule 1, error
  types come when we ship those errors.

The implementation is inline (no `utils.c` shim yet). When a
later chapter ships IPv4 checksum it can refactor both onto a
shared `inet_checksum` in utils.

### Layer5/ping.{h,c}

- Drops `PING_PROTO`, `PING_REQ`, `PING_REPLY`, `PingMsg`.
- Registers on protocol 1.
- Originate builds an `IcmpHdr` + 16-byte ASCII filler payload,
  fills `identifier` (low 16 bits of the Node pointer) and
  `sequence`, computes the checksum, calls
  `demote_packet_to_layer3` with proto=1.
- Receive verifies the checksum over the whole received buffer
  (drop on fail), then dispatches by `type`. ECHO_REQUEST copies
  the inbound payload verbatim, flips type to REPLY, recomputes
  the checksum, sends back per RFC 792's "echo back the data"
  rule. ECHO_REPLY prints
  `Ping reply : <node> : seq=N from <ip>`.
- New `ping_send_request_bad_checksum` test hook XORs one bit
  of the computed checksum before emit.

### nwcli.c

- New `run node X ping-bad <ip>` verb. Fires three valid pings
  to settle ARP both directions, then one ping with a corrupted
  checksum. The receiver MUST drop the corrupted one.

### Wire byte-order

ICMP fields on the wire are network byte order. `IcmpHdr.identifier`
and `IcmpHdr.sequence` go through `htons` / `ntohs`. The checksum
returned by `icmp_checksum` is in HOST byte order; the caller
`htons`-converts before storing.

The course's IP `src_ip` / `dst_ip` are still in HOST byte order
(course convention). ch11 honours real ICMP byte order for the
ICMP fields and leaves IP alone; PLAN.md says we close the IP
host-order debt when we wire TAP (Milestone 1 ch18) on any path
that touches the real wire.

## End-to-end demo

```
samtcpip> run node R0_re ping 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=1 from 20.1.1.1, replying
Ping recv : R1_re : ICMP echo request seq=2 from 20.1.1.1, replying
Ping reply : R0_re : seq=2 from 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=3 from 20.1.1.1, replying
Ping reply : R0_re : seq=3 from 20.1.1.2

samtcpip> run node R0_re ping-bad 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=1 from 20.1.1.1, replying
Ping reply : R0_re : seq=1 from 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=2 from 20.1.1.1, replying
Ping reply : R0_re : seq=2 from 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=3 from 20.1.1.1, replying
Ping reply : R0_re : seq=3 from 20.1.1.2
Ping recv : R1_re : ICMP checksum invalid (drop)
```

Three valid pings round-trip. The fourth (seq=99 internally,
flipped-bit checksum) hits the receiver's `icmp_checksum != 0`
gate and is dropped. No reply.

## Design choices

### Why we read bytes big-endian in the checksum

```c
unsigned int word = ((unsigned int)p[0] << 8) | p[1];
```

versus the classic textbook form that casts to `unsigned short*`
and reads native-endian. The big-endian read is byte-stable: the
result depends only on byte values, not host architecture. Real
network checksums need this property because the same bytes on
the wire must produce the same checksum on every machine that
processes them.

The cost is one extra `htons` on the caller side when storing
the result. Cheap.

### Why we drop in the receiver instead of fixing the sender

If the receiver tolerated bad checksums, the whole point of
RFC 1071 disappears. The receiver is the line of defense; the
sender is just one possible source of corruption (cable noise,
NAT rewriting, software bugs are others). The test hook lets
us exercise the receiver's gate without inventing a real
corruption source.

### Why no error type constants yet

PLAN.md rule 1: "Every chapter must move the curl-both-ways
needle." A constant we don't reference is dead code. When we
ship `ICMP Destination Unreachable` (whichever chapter), we
add `ICMP_DEST_UNREACH` then. Not before.

### Why identifier uses the Node pointer's low 16 bits

Real ICMP echo uses `identifier` to disambiguate concurrent
pings from different processes against the same destination
(the receiver echoes it back; the sender's process matches on
the value it sent). For us, the Node pointer is the closest
analog to a process identifier. The low 16 bits are unique
enough across the test topology's three nodes.

### Why 16-byte filler payload, not 56-byte like real ping

Linux ping defaults to 56 bytes of payload (timestamp + filler).
We pick 16 with a stable ASCII string because:
- 16 bytes is enough to demonstrate "the receiver echoes payload
  verbatim per RFC 792".
- A stable string makes the on-wire bytes deterministic - the
  same ping produces the same checksum every run, which makes
  test failures correlate with code changes rather than timing.

## What's NOT here

- ICMP error message types (Dest Unreach, Time Exceeded, Frag
  Needed, Redirect, etc). They come when we ship the chapters
  that emit them.
- Identifier/sequence matching on the sender side. We log every
  reply we receive; we don't verify the identifier matches what
  we sent. For a single-process simulator with one Node per
  pinger, no risk of confusion.
- ICMP receive on errors carried back to a pending TCP connect.
  Comes in Milestone 3 ch33.
- Real wire byte-order for IP src_ip / dst_ip. Closed at the
  TAP boundary in Milestone 1 ch18.

## Test discipline

| Axis              | Positive                                                    | Negative                                              |
|-------------------|-------------------------------------------------------------|-------------------------------------------------------|
| Happy round-trip  | `Ping recv : R1_re : ICMP echo request seq=`                | NO `ICMP checksum invalid` on clean traffic           |
| Happy round-trip  | `Ping reply : R0_re : seq=3 from 20.1.1.2`                  | (presence)                                            |
| Corrupted drop    | `Ping recv : R1_re : ICMP checksum invalid (drop)`          | NO `Ping reply : R0_re : seq=99` (bad seq never lands)|
| Drop count        | >=1 checksum-invalid                                        | (presence)                                            |
| ch10 regression   | ARP-miss + no-route paths still log their diagnostics       | (presence)                                            |

Strong gate: no reply for the corrupted seq=99. Asserts the
receiver actually enforces RFC 1071 verify, not just nominally
computes it.

## What's left

Next chapter (ch12): real 20-byte IPv4 header + RFC 1071 IP
checksum. Replaces the course's short / approximate IP header.
Refactors `icmp_checksum` and the new `inet_checksum` onto a
shared implementation in `utils.c`.

Then ch13 (UDP), then ch14 (TAP primitive), and Milestone 1
moves from "real bytes in the simulator" to "real bytes on a
real TAP wire."
