# ch26 - TCP orderly close (FIN states)

The full request-response-close cycle now works end to end.

## Plan deviation - ch24/25 skipped

PLAN.md called for:
- ch24 TCP retransmission + RTT/Karn
- ch25 TCP send-queue + pump-on-ACK

Both ARE shipped in the plan but represent **wire-quality
polish for lossy networks**. On a localhost TAP wire with zero
loss and zero reordering, curl works without them. Per
PLAN.md rule 1 ("would skipping make curl fail?"): no.

ch26 jumps the FIN states because those ARE needed for curl
to terminate the connection cleanly. ch24/25 can be backfilled
in a future loop (or skipped permanently if the MVP target
holds).

Honest record of the skip: this doc + the commit message.

## What landed

- New FSM states: `FIN_WAIT_1`, `FIN_WAIT_2`, `CLOSE_WAIT`,
  `LAST_ACK`. `TIME_WAIT` collapsed to `CLOSED` (no 2*MSL timer).
- `send_fin_ack(tcb)` helper.
- FIN handling in `tcp_recv`:
  - `ESTABLISHED + FIN` -> `CLOSE_WAIT`, ACK the FIN.
  - `FIN_WAIT_1 + FIN+ACK` -> `CLOSED` (peer combined paths).
  - `FIN_WAIT_2 + FIN` -> `CLOSED` (skipped TIME_WAIT).
  - `FIN_WAIT_1 + ACK` -> `FIN_WAIT_2`.
  - `LAST_ACK + ACK` -> `CLOSED`.
- `tcp_close(node, dst_ip, dst_port)` initiates the close.
- CLI: `run node X tcp-close <ip> <dport>`.

## End-to-end demo

```
samtcpip> config node R1_re tcp-listen 80
samtcpip> run node R0_re ping 20.1.1.2          ; warm ARP
samtcpip> run node R0_re tcp-syn 20.1.1.2 80    ; handshake
samtcpip> run node R0_re tcp-send 20.1.1.2 80 GET   ; data
samtcpip> run node R0_re tcp-close 20.1.1.2 80      ; active close
TCP close : R0_re : ESTABLISHED -> FIN_WAIT_1
TCP send : R0_re : FIN seq=8196 ack=4097 to 20.1.1.2:80
TCP recv : R1_re : FIN seq=8196 -> CLOSE_WAIT
TCP send : R1_re : ACK seq=4097 ack=8197 to 20.1.1.1:33333
TCP recv : R0_re : ACK ack=8197 -> FIN_WAIT_2

samtcpip> run node R1_re tcp-close 20.1.1.1 33333   ; passive close
TCP close : R1_re : CLOSE_WAIT -> LAST_ACK
TCP send : R1_re : FIN seq=4097 ack=8197 to 20.1.1.1:33333
TCP recv : R0_re : FIN seq=4097 -> CLOSED (skipped TIME_WAIT)
TCP send : R0_re : ACK seq=8197 ack=4098 to 20.1.1.2:80
TCP recv : R1_re : ACK ack=4098 -> CLOSED
```

Both sides land in CLOSED. Full half-close orchestrated, both
FINs traded, both final ACKs delivered.

## Design choices

### Why no TIME_WAIT

Real TCP holds in TIME_WAIT for 2*MSL (typically 60s) to
guarantee delayed segments don't confuse a future connection
reusing the 4-tuple. On a single-process simulator with
deterministic ISNs, the risk is zero.

A future "real-world TCP" chapter would add the timer.
Documented as collapsed.

### Why FIN check before ESTABLISHED data check

A FIN+ACK on an ESTABLISHED connection is a close signal, not
a data signal. The FIN branch must run first so a payload-less
FIN doesn't accidentally fall through to the no-op log.

### Why we DON'T auto-close from the recv side

Real TCP's CLOSE_WAIT is the application's responsibility to
finish. The app gets a "remote closed" notification and decides
when to call close(). Our simulator follows the same shape -
recv parks the TCB in CLOSE_WAIT; the test (or app, or CLI)
explicitly calls `tcp_close` to transition to LAST_ACK.

### Why we keep CLOSED TCBs in the list

Real Linux frees them. We leak them across the process
lifetime. For test scale (handful of connections) this is fine.
A future "TCB GC" chapter would walk + free.

## What's NOT here

- TIME_WAIT timer (collapsed).
- TCB free on CLOSED.
- CLOSING state (simultaneous close).
- Half-close semantics where data continues to flow from
  CLOSE_WAIT side.
- Retransmission of FIN if lost (ch24 skipped).
- Send-queue draining before FIN emit (ch25 skipped).

## Test discipline

The test asserts every transition by name; if a state machine
edit moves a single transition, that line of the test catches
it. Strong gates are the dump assertions at the end - both
TCBs MUST land in CLOSED for the close to be "complete."

## What's left

- ch27 RST handling (RST received -> immediate CLOSED;
  RST emit on bad SYN or unsolicited segment).
- ch28 pcap dump facility.

Then we've covered the MVP TCP needed for curl IN to work.
The next milestone (3) wires the active outbound side + DHCP
+ DNS for curl OUT.
