# ch12 - real 20-byte IPv4 header + IP checksum

The course's `IpHdr` was 22 bytes: `ttl`, `protocol`, and
`checksum` were `short` instead of the RFC 791 single bytes
(checksum is 2 bytes; ttl and protocol are 1 each). The
`checksum` field was never computed. ch12 fixes both.

## What landed

### 20-byte IpHdr (RFC 791)

```c
typedef struct IpHdr {
    unsigned int   version    : 4;
    unsigned int   ihl        : 4;
    unsigned char  tos;               // was: char not_used
    unsigned short total_length;
    unsigned short identification;
    unsigned int   unused_flag : 1;
    unsigned int   DF_flag     : 1;
    unsigned int   MORE_flag   : 1;
    unsigned int   frag_offset : 13;
    unsigned char  ttl;               // was: short
    unsigned char  protocol;          // was: short
    unsigned short checksum;          // was: short, never computed
    unsigned int   src_ip;
    unsigned int   dst_ip;
} IpHdr;
```

`_Static_assert(sizeof(IpHdr) == 20)` in layer3.c pins the
layout. A future edit that accidentally widens any field fails
the build immediately.

### Shared RFC 1071 in utils.c

`inet_checksum(data, len)` moves from inline-in-icmp.c to
utils.c. ICMP and IP both call it. ICMP's `icmp_checksum`
becomes a one-line wrapper so the more specific name still
works at call sites.

### Compute + verify + recompute

Three hook points in layer3.c:

1. **Originate** (`demote_packet_to_layer3`): after every header
   field is final, `ip->checksum = 0` then
   `ip->checksum = htons(inet_checksum(ip, 20))`. The htons is
   because `inet_checksum` returns host-order; the wire wants
   network order for byte-stability.

2. **Receive** (`layer3_pkt_recv_from_layer2`): right after
   casting `IpHdr*` and bounds-checking ihl, verify with
   `inet_checksum(ip_hdr, hdr_size) != 0` → drop. Self-consistency
   of RFC 1071 says a valid header summed in full yields 0.

3. **Forward TTL decrement**: TTL is in the checksummed area, so
   after decrement we zero and recompute. We skip RFC 1141's
   incremental-update trick - simpler is fine at this scale.

### Test hook + CLI

`l3_test_force_ip_csum_corruption(true)` makes the NEXT demote
call XOR one bit of the stored IP checksum. CLI verb
`run node X ping-bad-ip <ip>` fires 3 valid pings (settle ARP),
enables the hook, fires one corrupted ping (seq=88), disables.
The receiver MUST drop the corrupted one at L3 before any L4
dispatch.

## End-to-end demo

```
samtcpip> run node R0_re ping 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=1 from 20.1.1.1, replying
Ping recv : R1_re : ICMP echo request seq=2 from 20.1.1.1, replying
Ping reply : R0_re : seq=2 from 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=3 from 20.1.1.1, replying
Ping reply : R0_re : seq=3 from 20.1.1.2

samtcpip> run node R0_re ping-bad-ip 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=1 from 20.1.1.1, replying
Ping reply : R0_re : seq=1 from 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=2 from 20.1.1.1, replying
Ping reply : R0_re : seq=2 from 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=3 from 20.1.1.1, replying
Ping reply : R0_re : seq=3 from 20.1.1.2
L3 drop : R1_re : IP checksum invalid          ; seq=88 corrupted, dropped
```

Note: there is NO `ICMP echo request seq=88` log on R1. The L3
drop short-circuits before ICMP dispatch - exactly what the
test asserts as a strong gate.

## Design choices

### Why move inet_checksum to utils.c now

ch11 wrote `icmp_checksum` inline in Layer3/icmp.c. ch12 needs
the same RFC 1071 over a different protocol (IP). Two choices:
- Duplicate the code in layer3.c (next chapter needs UDP, then
  it duplicates again).
- Promote to utils.c.

We promote. icmp_checksum becomes a one-line wrapper so existing
call sites still read naturally.

### Why drop at L3 before L4

The IP checksum verifies the IP HEADER, not the L4 payload. A
header that fails the checksum means: addresses might be wrong,
protocol byte might be wrong, fragment offsets might be wrong.
Dispatching that packet to L4 means handing potentially-garbage
metadata to the L4 handler. Drop early.

The test asserts this explicitly: corrupted IP packets must
NEVER reach `Ping recv` on the receiver, even with a clean ICMP
checksum.

### Why htons on store, just like ch11

`inet_checksum` reads bytes big-endian and returns the
complemented sum as a HOST-ORDER `unsigned short`. Storing that
directly into a packed struct on a little-endian machine puts
the bytes in the wrong order on the wire - the receiver, which
reads big-endian, computes a different value and verify fails.

`htons` fixes it. The on-wire bytes are now big-endian, the
receiver reads them as big-endian, the self-consistency property
holds.

Same fix I had to apply in ch11. Cheap insurance: every place
we store a `inet_checksum` result wraps in `htons`.

### Why no RFC 1141 incremental update

Real Linux uses RFC 1141 to update the checksum after a TTL
decrement without rehashing the whole header (TTL is in the
high byte of a 16-bit word, so the delta is mechanical). At our
scale - one packet per ping per second - the saving is invisible.

Documented + deferred. A future "L3 perf pass" chapter could
swap in the incremental update behind the same function.

### Why _Static_assert, not a comment

A comment says "20 bytes." A `_Static_assert` makes the compiler
agree. We had a real bug for 11 chapters where IpHdr was 22 bytes
and nobody noticed because nobody read the sizeof. Now any edit
that breaks the size fails the build immediately.

### Why we don't fix src_ip / dst_ip byte order yet

The course stores both as HOST-order `unsigned int`. Real RFC
791 stores network-order. The checksum computation works either
way as long as both sides use the same convention - and they do.

PLAN.md rule 3 says we close this debt at the TAP boundary
(Milestone 1 ch18) on any new code that crosses it. Before then,
fixing src_ip / dst_ip byte order touches every other module +
breaks every test. Deferred.

### Why no PROGRESS.md update

We don't have one yet. ch11 didn't add it. PLAN.md is the
roadmap; per-chapter status lives in commit log + `git diff`.
A future chapter can introduce PROGRESS.md if useful.

## What's NOT here

- RFC 1141 incremental checksum update.
- IP options (we allow ihl >= 5 in the bounds check, but no
  parsing). When something needs options we add the parser.
- Source-IP / destination-IP wire byte-order fix. Deferred per
  PLAN.md rule 3 until the TAP-boundary chapter.
- Fragmentation + reassembly (ihl + flags + frag_offset are
  parsed but never consulted). Comes in Milestone 4.
- ICMP errors for bad IP fields (versus < 5, TTL=0, bad
  protocol, etc). They come when we ship those error types.
- ttl-expired ICMP Time Exceeded emit. ch12 logs and drops;
  the emit hook waits for the chapter that ships ICMP errors.

## Test discipline

| Axis                  | Positive                                                | Negative                                              |
|-----------------------|---------------------------------------------------------|-------------------------------------------------------|
| Happy round-trip      | `Ping reply : R0_re : seq=3 from 20.1.1.2`              | NO `IP checksum invalid` on clean traffic             |
| Bad IP drop           | `L3 drop : R1_re : IP checksum invalid`                 | (presence)                                            |
| L4 short-circuit      | (no positive)                                           | NO `ICMP echo request seq=88` on R1 (L3 drop before)  |
| L4 csum not consulted | (no positive)                                           | NO `ICMP checksum invalid` for corrupted-IP packets   |
| Drop count            | >=1 IP-csum drop                                        | (presence)                                            |
| ch11 ICMP regression  | `ICMP checksum invalid` for the ICMP-bad-csum fixture   | NO IP-csum drop on the ICMP-bad fixture               |

Strong gate: L4 short-circuit. The corrupted IP packet must
NEVER reach R1's ICMP handler. If the test fails this, the L3
drop happens too late and L4 sees garbage. Catches a regression
where someone moves the verify after the route lookup or after
local-delivery decision.

## What's left

Next chapter (ch13): real UDP. RFC 768 wire format + pseudo-
header checksum (a separate compute from the inet_checksum we
just shared, because UDP folds source IP + dst IP + protocol +
length into the hash). Will need port-bound handlers in a new
Layer4/udp module.

Then ch14 (TAP primitive), and Milestone 1 starts moving from
"real bytes in the simulator" to "real bytes on a real TAP
wire."
