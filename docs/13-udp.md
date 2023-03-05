# ch13 - real UDP (RFC 768 + pseudo-header checksum)

Third RFC protocol online. Completes Phase 0 of Milestone 1
("Real bytes" - ICMP, IP, UDP). Next chapter is ch14 (TAP
primitive) which starts wiring these bytes onto a real Linux
network interface.

## What landed

### Layer4/udp.{h,c}

- 8-byte `UdpHdr` (src_port, dst_port, length, checksum) packed,
  all NBO.
- `UdpPseudoHdr` (12 bytes: src_ip + dst_ip + zero + protocol +
  udp_length-NBO) prepended to the segment for the checksum hash.
- `udp_bind / udp_unbind / udp_lookup_binding`: per-Node port
  registry. Global `GlThread` of `UdpBinding { node, port,
  handler }`.
- `udp_send_pkt(node, dst_ip_host, src_port, dst_port, payload,
  len)`: builds the segment, picks src_ip via subnet match (or
  loopback fallback), runs the pseudo-checksum, htons-stores the
  result, hands to L3.
- `udp_recv`: L3-level dispatcher registered on protocol 17.
  Verifies the pseudo-csum (drop on bad), looks up the binding
  (drop with log if absent), calls the handler.
- `udp_test_force_csum_corruption(bool)`: XOR one bit pre-emit.

### Built-in apps

- `udp_echo_handler`: RFC 862-ish. Echoes payload back to
  `(src_ip, src_port)` via another `udp_send_pkt`.
- `udp_printer_handler`: prints, drops. Used as the originating
  src_port (12345) so echo replies land somewhere visible.
- `udp_install_default_handlers(topo)` binds {7 -> echo, 12345
  -> printer} on every Node.

### CLI

```
run node <name> udp <ip>           # send greeting to ip:7, src=12345
run node <name> udp-bad-csum <ip>  # ARP warmup + 1 bad-csum send
```

### nwcli + testapp wiring

`nwcli_install(topo)` now calls `udp_register()` and
`udp_install_default_handlers(topo)`. Same hook ch10 used for
ping.

## End-to-end demo

```
samtcpip> run node R0_re udp 20.1.1.2
UDP echo : R1_re : recv 19 bytes on port 7 from 20.1.1.1:12345, echoing
UDP echo : R1_re : recv 19 bytes on port 7 from 20.1.1.1:12345, echoing
UDP printer : R0_re : port 12345 from 20.1.1.2:7 : `hello-from-samtcpip`

samtcpip> run node R0_re udp-bad-csum 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=1 from 20.1.1.1, replying
Ping reply : R0_re : seq=1 from 20.1.1.2
...(3 ARP-warmup pings)...
UDP recv : R1_re : checksum invalid (drop)     ; pseudo-csum verify catches it
```

The corrupted send hits R1's L3 (IP csum is fine; only the UDP
checksum is flipped) but the pseudo-header verify drops it
before the echo handler runs. No reply comes back. Asserted as
strong gates in the test.

## Design choices

### Why pseudo-header (versus checksumming only the UDP segment)

RFC 768: the UDP checksum covers a 12-byte pseudo-header
(src_ip + dst_ip + protocol + UDP length) plus the UDP segment.
This catches misdelivery - if NAT or a buggy forwarder rewrote
the IP src/dst, the UDP-only checksum would still pass but the
pseudo-header version detects the change.

We honour it from day one. Tomorrow's NAT chapter (post-MVP) has
to recompute when it rewrites; if we shipped UDP-only csum, NAT
would silently break.

### Why htons-store, again

Same trap as ch11 and ch12. `inet_checksum` returns the
complemented sum as a host-order ushort. Storing directly puts
the bytes in the wrong order on the wire; receiver reads
big-endian and gets a different value; verify fails.

`htons(inet_checksum(...))` fixes it. This is the third place
the pattern appears - if a fourth shows up, it's a helper.

### Why we DON'T verify when stored csum is zero

RFC 768 explicitly allows the sender to set checksum=0 ("checksum
disabled"). The receiver MUST NOT verify in that case.

We always compute, so for our simulator's purposes the csum is
never zero on the wire. The branch is there for the chapter that
delivers real Linux UDP - some Linux apps send csum=0 and we
need to accept it.

### Why no ICMP Port-Unreach emit

The archive's UDP fires ICMP type=3 code=3 when no binding
exists. Per PLAN.md rule 1, we ship only what's needed today.
The test for ch13 doesn't exercise the no-binding path strongly
(see "What's NOT here"); when a future chapter ships ICMP
errors, the no-binding branch in udp_recv grows the emit call.

For now: log + drop.

### Why inline src_ip pick (not a shared helper)

ch11 ping.c picks src_ip via a near-identical lookup. The
archive's ch39 promoted this to a shared `node_pick_src_ip`.
Per PLAN.md rule 1 we don't ship the helper unless a third
caller appears.

A `TODO` comment in the inline code names the future helper so
the next person who duplicates this logic for TCP knows to
consolidate.

### Why printer port = 12345 (not 9999 or anything)

The archive picked 12345 and the choice is arbitrary. Sticking
with it means the simulator's test logs and ours match
character-for-character, which makes debugging easier when we
cross-reference patterns.

### Why udp_install_default_handlers binds on every Node

We have a multi-Node topology (R0 / R1 / R2). Every Node may
need to receive UDP. Per-Node binding lets each Node have a
DIFFERENT handler at port 7 if desired. The default
"all-Nodes bind echo+printer" is just a test convenience.

When we move to single-Node (the userspace stack), this becomes
"bind on the one Node" and the multi-Node loop collapses.

### Why we cap payload at 150

`demote_packet_to_layer3` has a 200-byte total cap from ch9.
Header is 20 (IP) + 8 (UDP) = 28. Payload cap is 200 - 28 = 172.
We use 150 to leave margin for the test fixture's filler.

A future chapter that ships fragmentation (Milestone 4)
removes this cap.

## What's NOT here

- ICMP Port-Unreach emit on no-binding. Logs + drops; the emit
  comes with the chapter that ships ICMP errors.
- Shared `node_pick_src_ip` helper. Inlined here; promote when
  TCP arrives.
- Real Linux csum=0 acceptance with a forced verify-off CLI.
  The branch exists but no test exercises it yet.
- Per-bound-port stats. Each binding is a (node, port,
  handler) triple; no packet counters.
- Source port allocation for outbound flows. Caller picks
  src_port explicitly. Ephemeral-port management comes in
  Milestone 3 (ch31).
- Concurrent send / receive on the SAME (node, port). UDP is
  connectionless; the binding handler runs synchronously on
  the recv thread.

## Test discipline

| Axis             | Positive                                                          | Negative                                              |
|------------------|-------------------------------------------------------------------|-------------------------------------------------------|
| Round-trip       | `UDP echo : R1_re : recv 19 bytes ... echoing`                    | NO `checksum invalid` on clean traffic                |
| Round-trip       | `UDP printer : R0_re : port 12345 from 20.1.1.2:7 :`              | (presence)                                            |
| Bad csum         | `UDP recv : R1_re : checksum invalid (drop)`                      | (presence)                                            |
| Bad csum gate    | (no positive)                                                     | NO `UDP echo : R1_re : recv 19 bytes` for the bad pkt |
| Bad csum gate    | (no positive)                                                     | NO `UDP printer : R0_re` in the corrupted run         |
| No spurious drop | (no positive)                                                     | NO `no binding for port` on the happy path            |
| Ping regression  | `Ping reply : R0_re : seq=3 from 20.1.1.2`                        | (presence)                                            |

Strong gates: echo handler MUST NOT fire AND printer MUST NOT
log for the corrupted send. Catches a regression where the
verify hook moves below the binding lookup, or someone removes
the htons on store and the bytes round-trip "by accident."

## What's left

Phase 0 of Milestone 1 done. ICMP, IPv4, UDP all real.

Next chapter (ch14): TAP primitive. `tap_open`, `tap_close`,
`tap_send`, `tap_recv` for `/dev/net/tun` operations. Standalone
helpers + CLI. Doesn't wire into the recv pipeline yet - that's
ch15. ch14 is "can we even talk to a TAP fd."

After that: ch15 (TAP recv -> pkt_receive), ch16 (send_pkt_out
-> TAP), ch17 (event-loop + locking), and so on. The bytes go
from simulated to real.
