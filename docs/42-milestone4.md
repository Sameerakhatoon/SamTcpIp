# ch42 - Milestone 4 sign-off: real-wire robustness

## What this chapter is

A cap chapter. No new wire-format code. Declares Milestone 4
done by running a single combined smoke test that drives all
four features added on this M4 pass:

| Feature                     | Chapter | What it gives us                  |
|-----------------------------|---------|-----------------------------------|
| IP fragmentation + reassembly | ch34  | datagrams > IP_MAX_FRAG_PAYLOAD   |
| PMTUD path cache + ICMP rcv | ch39    | dynamic per-dst MTU shrinkage     |
| TCP cwnd + slow start       | ch40    | sender ramps up safely            |
| TCP peer-window enforcement | ch41    | sender stops before receiver does |

## Going-in goal vs what was shipped

PLAN.md framed Milestone 4 as:

> Stack survives lossy WAN, variable MTU.

Concretely, after this run:
- Variable MTU: PMTUD cache exists, ICMP Type 3 Code 4 receive
  installs entries, originate path consults the cache. Variable
  MTU paths shrink (correct) but never grow (also correct,
  per RFC 1191).
- Lossy: cwnd halves on a loss event and slow-starts back. The
  peer-window gate prevents over-running a slow receiver. The
  two together model the heart of TCP-on-a-noisy-wire.

What we did NOT do, on purpose:
- **TCP retransmission.** Without an RTO timer, "loss" today is
  manual (`tcp-loss` CLI). Real impls fire automatically.
- **Wire emit of ICMP Frag Needed on forwarding.** Receive side
  is wired; emit side waits for a router with a smaller MTU
  than the originator. We don't have that in the test rig.
- **Out-of-order TCP receive buffer.** We drop and re-ACK.
- **Send-queue with drain-on-ACK.** Oversized send is refused
  (window-blocked log); real impls would queue.
- **Window scaling, SACK, ECN.** Each is its own RFC; none
  needed to prove the gate works.

All four are listed in PLAN.md's "out of scope" tail. None
gate the curl-both-ways goal.

## End-to-end demo

The sign-off test runs this script:

```
config node R1_re tcp-listen 80
run node R0_re ping 20.1.1.2          # ARP warm
run tcp-rwnd 100                      # peer will advertise small window
run node R0_re tcp-syn 20.1.1.2 80
run node R0_re tcp-send-big 20.1.1.2 80 200    # gate blocks
run node R0_re tcp-send-big 20.1.1.2 80 40     # cwnd grows
run node R0_re tcp-send-big 20.1.1.2 80 40     # cwnd grows
run node R0_re tcp-loss 20.1.1.2 80    # cwnd snaps back
run pmtu set 20.1.1.2 60               # discovered tighter path
run node R0_re udp-big 20.1.1.2 250    # fragments finer
run pmtu clear
```

And asserts:
- 6+ IP fragment emits (ch34 + ch39 working together)
- "PMTU install: dst=20.1.1.2 mtu=60" + "PMTU clear all"
- init cwnd=1460 ssthresh=65535 peer_win=100
- slow-start growth line(s)
- LOSS line: cwnd resets to one SMSS
- "window-blocked ... len=200 > min(cwnd=1460, peer_win=100)"
- 40-byte send went through
- Ping regression still works

## State after Milestone 4

```
M1  ch21   on the wire             host pings us, we ping host
M2  ch29   TCP passive             curl OUT works against in-stack HTTP
M3  ch33   TCP active + autoconfig  curl from inside our stack works
M4  ch42   real-wire robustness    frag/PMTUD/cwnd/peer-window
M5  ch38   operational hygiene     bounded growth, clean exit, log levels
```

Both directions of curl work. The stack ramps up sender pace,
respects the receiver, and shrinks fragments to discovered MTU.
It exits cleanly on signal and can be told to shut up. The
phrase "userspace TCP/IP stack" is now true with no asterisks.

## What's left (optional polish)

- TCP retransmission timer (the only real "wait for ACK" loop
  we don't have)
- Send queue + drain-on-ACK (so window-blocked becomes queue-
  and-retry rather than refuse)
- ICMP Frag Needed emit on forwarding (so we'd be a polite
  middlebox, not just a polite receiver)
- IP fragment overlap detection (we trust the wire)

Each is a Phase 6+ chapter, not an MVP gate.
