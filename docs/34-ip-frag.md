# ch34 - IP fragmentation + reassembly (RFC 791)

Milestone 4 begins. The stack now correctly fragments large
outbound payloads into 100-byte L3 chunks and reassembles
incoming fragments by their 4-tuple identity.

## What landed

- `IP_MAX_FRAG_PAYLOAD=100` exposed in `layer3.h`. Small so
  fragmentation is visible in tests; not the real-Linux 1500
  default.
- `demote_packet_to_layer3` now:
  - Picks route + src once.
  - Increments a global `g_ip_id_next` for the datagram id.
  - Splits the payload into 8-byte-aligned chunks (except the
    final tail, which can be sub-8).
  - For each chunk, calls a new `emit_one_ip_fragment` helper
    that fills in `identification`, `MORE_flag`, `frag_offset`,
    recomputes the checksum, and dispatches via the existing
    push-down path.
- Receive path (`layer3_pkt_recv_from_layer2`) detects
  fragments by `MORE_flag != 0 || frag_offset != 0`:
  - Looks up / creates a `ReassemblyEntry` keyed by
    `(src_ip, dst_ip, protocol, id)`.
  - Copies the chunk into `buf[frag_offset*8 ...]`.
  - Tracks 8-byte slot coverage to know when reassembly is
    complete (`have_bytes >= expected_bytes`).
  - On the MF=0 fragment, sets `expected_bytes = frag_off*8 +
    len`.
  - On completion, calls `promote_pkt_to_layer4` with the full
    reassembled payload, frees the entry.
- UDP `payload_size` cap raised from 150 to 1400 (the 150 was a
  pre-fragmentation artifact).
- New CLI `run node X udp-big <ip> <bytes>` fires a >100-byte
  UDP that triggers fragmentation.

## End-to-end demo

```
samtcpip> run node R0_re udp-big 20.1.1.2 250
IP frag emit : R0_re : id=10 off=0   len=96 MF=1
IP frag emit : R0_re : id=10 off=96  len=96 MF=1
IP frag emit : R0_re : id=10 off=192 len=66 MF=0     ; tail, MF=0
IP frag recv : R1_re : id=10 off=0   len=96 MF=1 (have 96/0)
IP frag recv : R1_re : id=10 off=96  len=96 MF=1 (have 192/0)
IP frag recv : R1_re : id=10 off=192 len=66 MF=0 (have 264/258)
IP frag done : R1_re : id=10 total=258 bytes
UDP echo  : R1_re : recv 250 bytes on port 7 from 20.1.1.1:12345, echoing
IP frag emit : R1_re : id=11 off=0   len=96 MF=1       ; reply also fragments
...
```

Both directions fragment; both directions reassemble. UDP echo
sees the full 250-byte payload, not the 96-byte first fragment.

## Design choices

### Why 100 bytes (not 1500)

Linux defaults to ~1500 (Ethernet MTU). At that size, a 250-byte
UDP wouldn't fragment - the test wouldn't exercise fragmentation.
We use 100 so fragmentation is observable in tests; a future
"per-interface MTU" chapter can promote this to a real knob.

### Why we round chunks to 8-byte multiples

RFC 791 frag_offset is in 8-byte units. Any non-final fragment
MUST be a multiple of 8. We chunk at `(IP_MAX_FRAG_PAYLOAD/8)*8`
bytes (= 96 for the 100 limit) so the offset arithmetic stays
clean. The LAST fragment can be any size; the receiver knows
because MF=0.

### Why slot-based completion tracking

A naive "did I get all bytes?" check needs the receiver to know
the total before completion. With out-of-order arrival, the
LAST fragment could come first; we can't trust offsets alone.

Slot tracking covers the worst case: we mark every 8-byte slot
when written, count them, compare to expected (set on MF=0).
Cheap, robust against reorder. Bitmap'd boolean per-slot.

### Why we don't have a reassembly timeout

Real Linux drops partial reassemblies after IP_REASM_TIMEOUT_MS.
We declared `IP_REASM_TIMEOUT_MS=30000` but no thread enforces
it. A future "background ticker" chapter wires the cleanup.
For now, a partial reassembly leaks until process exit.

### Why fragments share src_ip / dst_ip / proto / id

That's the RFC 791 reassembly key. The receiver doesn't care
about ttl, flags, etc on subsequent fragments.

### Why TTL on each fragment

Each fragment is an independent IP datagram on the wire. TTL
counts hops; each fragment passes through the same hops, so
each gets the same TTL initially. They get decremented
independently if any go through a router (irrelevant for our
direct-connected test).

## What's NOT here

- Per-interface MTU (the 100-byte cap is hardcoded).
- DF flag handling (we'd emit ICMP Frag Needed on DF set + too
  big; deferred to ch35 if we ship PMTUD).
- Reassembly timeout enforcement (no background ticker).
- Fragment overlap detection (RFC 5722 says drop on overlap;
  we silently overwrite).
- Reassembly statistics (count of in-flight, completed, timed
  out).

## Test discipline

| Axis                | Positive                                                          |
|---------------------|-------------------------------------------------------------------|
| Emit fragments      | >=3 `IP frag emit : R0_re : id=`                                  |
| Recv fragments      | `IP frag recv : R1_re :`                                          |
| Reassembly complete | `IP frag done : R1_re :`                                          |
| L4 delivery         | `UDP echo : R1_re : recv 250 bytes`                               |
| Reply fragments     | `IP frag emit : R1_re :`                                          |
| Small no-frag       | No `IP frag emit` on a plain ping                                 |
| Ping regression     | `Ping reply : R0_re : seq=3 from 20.1.1.2`                        |

## What's left

ch35: PMTUD + ICMP Frag Needed (DF flag path).
ch36: TCP congestion control (cwnd, ssthresh).
ch37: TCP real peer-window enforcement.
ch38: Milestone 4 sign-off.
