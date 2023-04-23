# samtcpip - userspace TCP/IP stack

A userspace TCP/IP stack on a Linux TAP device. Both directions.
Real RFC wire bytes. One chapter at a time, one commit at a time,
one test per chapter.

## End goal

Two-way curl over a real TAP wire:

1. A real Linux process can `curl http://<our-tap-ip>/` and get
   a response. (Inbound TCP works.)
2. Our stack can `curl http://realhost/` and get a response.
   (Outbound TCP + DNS + default route + DHCP-or-static IP all
   work.)

When both flows pass on a real host, the project name is true.

## Hard scope rules

These are the rules we broke building the simulator. We don't
break them again.

1. **Every chapter must move the curl-both-ways needle.** Before
   starting a chapter, ask: "if I skipped this, would curl
   eventually fail anyway?" If no, the chapter is out of scope.

2. **TAP first, protocol breadth never.** Real wire integration
   precedes routing protocols, firewalls, NAT, conntrack, IPv6.
   None of those touch the plan until both directions of curl
   work.

3. **Byte order: real on every new path.** Old code may keep its
   host-order debt as long as it never touches a TAP-attached
   path. New code on TAP-attached paths uses real network byte
   order from day one.

4. **One Node only.** The course shipped a multi-Node `Graph`
   simulator. We keep `Node*` as a parameter for API continuity
   but the userspace stack is exactly one Node. No `R0`, `R1`,
   `R2`. The single Node is the process itself.

5. **No simulator-only features.** STP, VLAN beyond basic, L2
   switching between simulated Nodes, multi-Node routing
   protocols, multi-Node conntrack - all stay out. We are an
   endpoint, not a topology.

6. **Honest inventory in every doc.** Every chapter doc has a
   "What's NOT here" section naming what was deferred + why.


8. **Commit hygiene.**
   - One chapter = one commit. Format `chN: short topic`.
   - Bug-fix commits use `gNN:` prefix referencing the chapter
     they fix.
   - Author `Sameerakhatoon <sameerakhatoon05@gmail.com>`.
   - No Claude co-author.

9. **Tests.** Every chapter ships a bash E2E test under
   `tests/NN-*.sh`. Test drives the actual `testapp` binary,
   asserts both positive (what should happen) and negative
   gates (what should not happen). No mocks.

10. **Docs.** Every chapter ships `docs/NN-topic.md` with:
    - What landed
    - End-to-end demo (the exact log lines)
    - Design choices
    - What's NOT here (honest inventory)
    - Test discipline (the gate table)
    - What's left

## Current state - end of ch10

We are at commit `815b3ab`. The course has taught us:

- Generic graph + glthread (ch1)
- Network properties (NodeNwProp, IntfNwProps) (ch2)
- Hand-rolled CLI (ch3)
- Per-Node UDP socket + select recv thread (ch4) - the
  simulator's wire, NOT real TAP.
- L2 ARP (ch5)
- MAC learning + L2 switching (ch6)
- 802.1Q VLAN (ch7)
- L3 routing table + LPM (ch8)
- L3 forwarding pipeline (ch9)
- Ping with a homegrown `PING_PROTO=201 + PingMsg` (ch10)

What we do NOT have:
- Real ICMP (homegrown protocol number).
- Real IPv4 header (course's is short / approximate).
- UDP / TCP at any layer.
- TAP device.
- Any real-wire interop.
- DHCP, DNS, sockets API.

This is the starting line.

## Milestones

### Milestone 1 - "We're on the wire" (ch11 → ch21, 11 chapters)

Every packet on a real TAP device. ARP works both ways. Real
ping round-trips with a real Linux host.

```
ch11  real ICMP (RFC 792 + RFC 1071 checksum)
ch12  real 20-byte IPv4 header + RFC 1071 IP checksum
ch13  real UDP (RFC 768 + pseudo-header checksum)
ch14  TAP primitive (open, close, read, write)
ch15  TAP recv wired into pkt_receive
ch16  send_pkt_out targets a TAP fd
ch17  event-loop + threading + locking model
ch18  static TAP-IP CLI + interface bring-up
ch19  ARP two-way (initiate + answer over TAP)
ch20  gratuitous ARP on IP assignment
ch21  end-to-end: host pings us, we ping host (tcpdump verified)
```

Goal hit at ch21: tcpdump on the host shows our stack's frames
with correct wire bytes.

### Milestone 2 - "TCP passive" (ch22 → ch28, 7 chapters)

curl on the host can connect to our TCP listener and get a
response.

```
ch22  TCP 3-way handshake (parse incoming SYN, send SYN-ACK)
ch23  TCP data + cumulative ACK
ch24  TCP retransmission + RTT/Karn
ch25  TCP send-queue + pump-on-ACK
ch26  TCP orderly close (FIN states + TCB free)
ch27  TCP RST handling
ch28  packet capture facility (.pcap dump on enable)
```

Goal hit at ch28: `curl http://<our-tap-ip>/` returns "hello"
via static `/etc/hosts` on the host.

### Milestone 3 - "TCP active + autoconfig" (ch29 → ch35, 7 chapters)

Our stack can curl OUT to a real internet host.

```
ch29  source address selection
ch30  default route handling
ch31  outbound port allocation (ephemeral range)
ch32  TCP active open (tcp_connect)
ch33  ICMP error receive (abort pending connects)
ch34  DHCP client (DORA exchange with dnsmasq)
ch35  DNS client (resolve hostnames via configured resolver)
```

Goal hit at ch35: from inside our stack, `curl http://realhost/`
works.

### Milestone 4 - "Real-wire robustness" (ch36 → ch39, 4 chapters)

Stack survives lossy WAN, variable MTU.

```
ch36  IP fragmentation + reassembly
ch37  PMTUD + ICMP Frag Needed
ch38  TCP congestion control (cwnd, ssthresh)
ch39  TCP real peer-window enforcement
```

Goal hit at ch39: stack runs against a noisy, multi-MTU wire
and still works.

### Milestone 5 - "Operational hygiene" (ch40 → ch42, 3 chapters)

Stack is something a person could actually run.

```
ch40  logging discipline (debug/info/warn/error levels)
ch41  signal handling + clean shutdown
ch42  ARP + MAC aging
```

Goal hit at ch42: run our stack for an hour, no leaks, no
unbounded growth, clean exit on Ctrl-C.

## Total: 32 chapters across 5 milestones

At ch42 we are done. The phrase "userspace TCP/IP stack" is
true without qualifiers.

## Shipped vs planned (post-mortem)

The plan above was the going-in roadmap. Actual ship order
diverged - chapters were collapsed where the work was
smaller than expected, and a few PLAN chapters were
deliberately deferred when they didn't move the curl needle
(see commit notes). Real chapter map as shipped:

```
M1  ch11-21   shipped as planned
M2  ch22-29   ch24 (rtx) + ch25 (sendq) deferred; sign-off at ch29
M3  ch30-33   collapsed; sign-off at ch33 (no DHCP/DNS - static
              config is enough for the curl-both-ways goal)
M4  ch34       only IP frag shipped; PMTUD/cwnd/peer-window
              deferred (real-wire is good enough without them
              for the test rig)
M5  ch35-38   aging, signals, log levels, sign-off
```

Every shipped chapter has docs/NN-*.md + tests/NN-*.sh.
Deferrals are documented in each chapter's "what's NOT here"
section; see also the PLAN out-of-scope list below for what
stays out of scope.

**Milestone 5 signed off at ch38.** Both directions of curl
work; stack survives long runs and exits cleanly. MVP done.

## Explicitly out of scope (Phase 6+, post-MVP)

If we want any of these AFTER ch42, they are separate
milestones and each gets explicit ROI vs cost:

- LD_PRELOAD socket shim (real apps use our stack)
- IPv6
- DNS server, DHCP server
- RIP, OSPF, BGP
- Conntrack, NAT (SNAT, DNAT, ICMP NAT)
- ICMP error breadth as emitter (Host Unreach, Port Unreach,
  Protocol Unreach, Redirect)
- Out-of-order TCP receive
- TCP MSS reduction on PMTUD
- Half-close TCP semantics
- Real FCS (verify need first; TAP usually strips)
- STP, VLAN polish
- Performance work (kernel-bypass territory)
- Socket options (NODELAY, KEEPALIVE)

If we touch any of these before ch42 lands, we have broken the
plan. Stop and reread Rule 1.

## Reference

The simulator we built between ch11-ch71 of the previous run
lives at `~/projects/samtcpip-sim/`. When stuck for a working
pattern (real ICMP header, RFC 1071 checksum, TCP FSM), look
there. Do NOT copy whole chapters. Each chapter here ships
under the rules above, against a real TAP wire, not a simulator.
