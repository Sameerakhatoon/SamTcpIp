# ch16 - send_pkt_out targets the TAP fd

Closes the second half of Phase 1's egress story. ch15 gave
us recv from the kernel TAP into `pkt_receive`. ch16 makes
the symmetric path: when `send_pkt_out` is called with an
oif that matches the TAP-attached `Interface*`, the frame
goes to `g_tap_fd` instead of the UDP-loopback wire.

After ch16 the simulator is half-real: any path that uses
the TAP-attached interface as oif IS REAL WIRE. Paths that
don't (R1 -> R2 in the test topology) stay on the UDP
simulator wire. The two coexist until we eventually collapse
to a single Node per PLAN.md rule 4.

## What landed

### tap.{h,c} additions

```c
bool tap_is_attached_iif(Interface* iif);
long tap_write_frame(const void* buf, size_t len);
```

`tap_is_attached_iif` returns `true` iff `iif == g_tap_iif`
AND we have a TAP attached. Safe to call before
`tap_attach`; returns false.

`tap_write_frame` writes the raw frame to `g_tap_fd` (which
the kernel sees as inbound on the TAP). Logs
`TAP send : N bytes via <node>/<iif>` on success.

### comm.c::send_pkt_out

A 6-line branch at the top of `send_pkt_out`:

```c
if(tap_is_attached_iif(oif)){
    long n = tap_write_frame(pkt, pkt_size);
    return n > 0 ? 0 : -1;
}
```

The branch is BEFORE the UDP-loopback path. When the oif is
TAP-attached, the loopback path is never taken; the function
returns directly after writing to the TAP.

No aux header. The UDP-loopback wire prepends a 16-byte
peer-interface-name because the receiver socket is at the
Node level (one socket per Node, multiple ifaces share it)
and the receiver needs to know which iface the frame "came
in on." The TAP doesn't have that problem - the kernel
delivers raw ethernet frames; our receiver's pkt_receive
already knows the iif (it's `g_tap_iif`, set at attach).

## End-to-end demo (root)

```
samtcpip> run tap attach R0_re samtap0 eth0/0
TAP opened : ifname=samtap0 fd=4
TAP attach : samtap0 -> R0_re/eth0/0 fd=4
TAP recv thread started

samtcpip> run node R0_re ping 20.1.1.2
TAP send : 38 bytes via R0_re/eth0/0       ; ARP request, real wire
TAP send : 38 bytes via R0_re/eth0/0       ; retry
TAP send : 38 bytes via R0_re/eth0/0       ; retry
; no Ping recv on R1_re - R1 is the SIMULATOR side, not the wire

samtcpip> run tap detach
```

In a real LAN with the host kernel having the `samtap0`
interface up and a peer on 20.1.1.2, the ARP request would
reach a real ARP responder; the reply would come back through
the recv thread; the ping would round-trip on real wire.

For our test under root (no real peer): the ARP retry just
runs out. That's expected - ch16 is about the egress hook,
not about end-to-end interop. ch21 is the milestone goal
where real interop demonstrably works.

## End-to-end demo (non-root)

Attach fails at TUNSETIFF, no behavior change, the existing
ping round-trip on the simulator wire works exactly as
ch11/12/13/15 left it:

```
samtcpip> run tap attach R0_re samtap0 eth0/0
TAP ioctl TUNSETIFF failed : Operation not permitted (errno=1)

samtcpip> run node R0_re ping 20.1.1.2
Ping recv : R1_re : ICMP echo request seq=1 from 20.1.1.1, replying
...
Ping reply : R0_re : seq=3 from 20.1.1.2
```

The `tap_is_attached_iif` check returns false (no TAP), and
send_pkt_out falls through to the UDP-loopback path.

## Design choices

### Why the branch is in send_pkt_out, not in L2

The L2 sender (`layer2_pkt_push_down_to_layer2_for_l2routing`)
builds the ethernet frame and calls `send_pkt_out`. Doing the
TAP branch at L2 would mean adding the check to every L2 call
site that emits.

Putting it at the bottom of the egress (`send_pkt_out` is the
ONE function every emit funnels through) means a single hook
catches ARP requests, ICMP, UDP, TCP-when-it-arrives - all of
them. Same reasoning ch65 in the simulator used for FCS install.

### Why no peer aux header on TAP

The UDP-loopback wire's 16-byte aux prefix solves a problem
TAP doesn't have. UDP loopback: receiver is a Node with one
socket; aux says "this came in on intf X." TAP: kernel sends
us a frame; our recv thread already knows which iif (the
attached one). The recv side accepts the frame "as-is."

We must make sure that the SEND side matches. ch16 sends the
raw frame with no prefix - what the kernel sees is exactly
the ethernet bytes we built.

### Why we return after the TAP branch

The two wires are mutually exclusive for a given oif. If the
TAP is attached to eth0/0, then eth0/0's other end IS the
kernel - there's no peer Node on the UDP wire. Sending to
BOTH would be wrong (duplicate frame).

If a future chapter wants to mirror traffic for debugging,
that's a different feature with its own toggle.

### Why we log every TAP send

ch15 logs every TAP recv. Symmetry helps debugging - when an
ARP exchange fails to round-trip, the logs show whether the
frame even went out the wire. The volume is fine for our
test scale; a future "log level" knob (ch40 in the plan) can
gate it.

### Why we don't track per-frame TAP statistics

Same calculus as ch15. The recv log + send log gives operators
a per-frame trace. Aggregate counters come with the equivalent
of ch68 from the simulator era; for now we log+infer.

### Why the test asserts "Ping recv on R1_re must NOT appear"

That's the cleanest possible proof that the routing
changed. Pre-ch16, the UDP-loopback wire would carry the
frame to R1_re's socket and the L2/L3 stack on R1_re would
process it. Post-ch16, the frame goes to TAP instead - R1_re
sees nothing.

If a regression accidentally also sent on the UDP wire (or
removed the early-return after the TAP write), R1_re would
see the frame again and the test would fail.

## What's NOT here

- Multi-TAP (one per Node). Single static `g_tap_fd`.
- Send-side stats. Log lines only.
- Promiscuous mode toggle. The TAP delivers everything the
  kernel routes to its other end; that's fine for ch16.
- BPF filtering on the TAP fd.
- Synchronous read-after-write on the TAP for self-test.
  Linux delivers the frame to the OTHER side of the TAP
  (the kernel's network stack), not back to our recv fd.
- Verifying frames with tcpdump from inside the test.
  ch21 is the milestone goal where real interop matters;
  ch16 is the plumbing.

## Test discipline

| Axis             | Positive (root)                                          | Positive (non-root)                                | Negative                                              |
|------------------|----------------------------------------------------------|----------------------------------------------------|-------------------------------------------------------|
| Egress on TAP    | `TAP send : N bytes via R0_re/eth0/0` (>=1)              | -                                                  | -                                                     |
| Loopback bypass  | -                                                        | -                                                  | NO `Ping recv : R1_re :` when TAP attached            |
| Loopback bypass  | -                                                        | -                                                  | NO `Ping reply : R0_re :` when TAP attached           |
| Pass-through     | -                                                        | `Ping reply : R0_re : seq=3 from 20.1.1.2`         | NO `TAP send :` (attach failed)                       |
| No-TAP run       | -                                                        | -                                                  | NO `TAP send :` when TAP never attached               |
| Regression       | ping + UDP still work without TAP                        | ping + UDP still work                              | -                                                     |

Strong gate: under root with TAP attached, R1_re's
`Ping recv` MUST NOT appear. If that log shows up, ch16
broke its central promise (egress is mutually exclusive
between TAP and loopback).

## What's left

ch17: event-loop + threading + locking. We now have two
recv threads (UDP loopback + TAP) both calling pkt_receive.
ch17 reads the path under both threads and either documents
its safety, adds locks, or restructures. Then ch18 adds the
TAP-IP CLI + interface bring-up; ch19 wires ARP two-way over
real wire; ch20 GARP; ch21 the milestone goal.

Phase 1 of Milestone 1 is 4 chapters in (14, 15, 16, 17 next).
6 to go to reach the goal (host-pings-us / we-ping-host with
tcpdump verified).
