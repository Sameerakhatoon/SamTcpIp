# ch27 - TCP RST handling

Three branches per RFC 793 sec 3.4 / 3.9:

A. **RST received on any TCB** -> immediate transition to CLOSED.
B. **SYN to a port with no listener** -> emit RST|ACK.
C. **Non-SYN segment for an unknown 4-tuple** -> emit bare RST
   (skip if the inbound is itself RST; no ping-pong).

## What landed

- `send_rst_segment(node, local_ip, local_port, remote_ip,
  remote_port, seq, ack, with_ack)` builds + sends a bare RST.
  No options; 20-byte header.
- `tcp_recv` plugs the three branches:
  - SYN to closed port: emits RST|ACK with `seq=0, ack=seq+1`.
  - Unknown 4-tuple non-SYN: emits RST with seq/ack derived from
    the inbound flags (different conventions for ACK-bearing vs
    not, per RFC 793).
  - RST in any state: TCB goes CLOSED.

## ch27 bug fix that took me a minute

`tcb_alloc` was calling `glthread_add_last(&g_tcbs, ...)` without
first running `ensure_tcbs_init`. The g_tcbs list head was
zero-initialised but not glthread-initialised, so the list
operations operated on a stale head.

The visible symptom: a `show node X tcp` BEFORE any TCB alloc
triggered `tcp_dump` which called `ensure_tcbs_init`, after
which everything worked. Without that touch, the SYN_SENT TCB
added by `tcp_send_syn` was never findable by `tcb_find` on the
recv path.

Fixed in this chapter (`ensure_tcbs_init` at the top of
`tcb_alloc`). Comment names ch27 as the fixer.

## End-to-end demo

```
samtcpip> run node R0_re ping 20.1.1.2          ; warm ARP
samtcpip> run node R0_re tcp-syn 20.1.1.2 9999  ; closed port
TCP send : R0_re : SYN seq=8192 to 20.1.1.2:9999
TCP recv : R1_re : SYN to closed port 9999 -> RST
TCP send : R1_re : RST|ACK seq=0 ack=8193 to 20.1.1.1:33333
TCP recv : R0_re : RST received in state=SYN_SENT -> CLOSED

samtcpip> show node R0_re tcp
TCP TCBs : R0_re :
  [0] state=CLOSED local=33333 remote=20.1.1.2:9999
```

## Design choices

### Why RST + ACK on SYN to closed port

RFC 793: a RST in response to a SYN must acknowledge that SYN's
sequence number. So we send RST|ACK with `ack = seq + 1`.

### Why bare RST (no ACK) for unknown-4-tuple non-SYN

RFC 793 sec 3.4 specifies different RST construction depending
on whether the offending segment had an ACK flag. The seg has
ACK -> our RST uses `seq=their_ack, ack=0`, no ACK flag. No
ACK -> our RST uses `seq=0, ack=their_seq+len`, with ACK flag.

### Why we don't RST FIN-only

A FIN to ESTABLISHED is the normal close path (ch26 handles).
A FIN to a non-existent TCB falls through to the unknown-tuple
path which sends RST. Same code, no special case needed.

### Why RST received goes straight to CLOSED

RFC 793: RST is unconditional abort. No ACK, no nothing - the
peer signaled "this connection is dead." We MUST NOT keep
sending. Immediate transition + log.

## What's NOT here

- RST validity check (real TCP checks the inbound seq is inside
  the receive window before accepting RST; we accept any RST).
- Outbound RST in response to a "weird" segment in mid-state
  (e.g. ACK in SYN_SENT with wrong ack number).
- Challenge-ACK against blind reset attacks (RFC 5961).

## Test discipline

| Axis              | Positive                                                                | Negative                                              |
|-------------------|-------------------------------------------------------------------------|-------------------------------------------------------|
| Closed-port RST   | `TCP recv : R1_re : SYN to closed port 9999 -> RST`                     | -                                                     |
| RST received      | `TCP recv : R0_re : RST received in state=SYN_SENT -> CLOSED`           | -                                                     |
| TCB landed CLOSED | `state=CLOSED local=33333 remote=20.1.1.2:9999`                         | -                                                     |
| Handshake regr    | full ch22 ESTABLISHED still works                                       | -                                                     |

## What's left

ch28: packet capture facility. Writes pcap-format dumps so a
tcpdump-style trace can be assembled offline.

Then the Milestone 2 goal: under root, attach TAP + configure
+ listen + `curl http://<our-tap-ip>/` works.
