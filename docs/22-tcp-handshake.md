# ch22 - TCP 3-way handshake

Milestone 2 begins. The third RFC L4 protocol comes online -
RFC 793 TCP, but for ch22 only the handshake. Data, retransmit,
close, RST all live in their own chapters.

## What landed

- 20-byte `TcpHdr` packed (RFC 793 layout).
- Pseudo-header checksum (same algorithm as UDP - 12 pseudo
  bytes prepended to the segment for the inet_checksum hash).
  The protocol byte is 6 (TCP) instead of 17 (UDP).
- Per-Node `Tcb` list with FSM: `CLOSED -> LISTEN -> SYN_RECEIVED -> ESTABLISHED`
  on the passive side; `CLOSED -> SYN_SENT -> ESTABLISHED` on
  the active side. No states past ESTABLISHED yet.
- `tcp_listen(node, port)` installs a passive socket (TCB in
  LISTEN with no peer 4-tuple).
- `tcp_send_syn` allocates a SYN_SENT TCB and emits a SYN with
  an MSS option (1460 default). It also stashes our ISN.
- Receive handler walks the SYN -> SYN-ACK -> ACK exchange in
  both directions, parses the peer's MSS, transitions states.
- MSS option parsing (kind 2 len 4) - other options skip via
  their length byte.

## End-to-end demo

```
samtcpip> config node R1_re tcp-listen 80
TCP listen : R1_re : port 80

samtcpip> run node R0_re ping 20.1.1.2          ; warm ARP both ways
Ping reply : R0_re : seq=3 from 20.1.1.2

samtcpip> run node R0_re tcp-syn 20.1.1.2 80
TCP send : R0_re : SYN seq=8192 to 20.1.1.2:80
TCP recv : R1_re : SYN seq=8192 from 20.1.1.1:33333 (peer_mss=1460) -> SYN_RECEIVED
TCP send : R1_re : SYN-ACK seq=4096 ack=8193 to 20.1.1.1:33333
TCP recv : R0_re : SYN-ACK seq=4096 ack=8193 (peer_mss=1460) -> ESTABLISHED
TCP send : R0_re : ACK seq=8193 ack=4097 to 20.1.1.2:80
TCP recv : R1_re : ACK seq=8193 ack=4097 -> ESTABLISHED

samtcpip> show node R0_re tcp
TCP TCBs : R0_re :
  [0] state=ESTABLISHED local=33333 remote=20.1.1.2:80 peer_mss=1460
```

Full 3-way. Both sides know each other's MSS. Both TCBs sit in
ESTABLISHED ready for data (next chapter).

## Design choices

### Why pre-warm ARP with ping

A cold TCP handshake hits an ARP miss on the SYN-ACK path
(R1 needs to learn R0's MAC to reply). The simulator's L3 drops
ARP-miss packets without retry today. The simulator's ping
fixture pre-warms ARP both ways; the handshake test reuses it.

In a real-wire scenario (TAP under root), the host kernel's ARP
machinery handles this transparently. The simulator's lack of
ARP retry is a deferred simplification.

### Why deterministic ISN

`iss = 0x1000` (server) / `0x2000` (client). Real TCP picks a
quasi-random ISN (RFC 1948 / 6528). Deterministic IRN makes the
test assertions readable; ISN randomisation comes when active-
open gets its own chapter.

### Why htons-store on the checksum

Same trap as ch11/12/13. `inet_checksum` returns the
complemented sum in host order; the wire wants NBO. Without
`htons`, the receiver reads the bytes back as the byte-swapped
value and the self-consistency property fails.

### Why minimal active-open in ch22

PLAN.md ch22 named "passive 3-way handshake." But the test
needs SOME way to drive a SYN; without active-open we'd need a
hand-built ACK CLI to complete the handshake. The minimal
SYN_SENT TCB + SYN-ACK matcher is ~30 lines and makes the test
self-contained.

The "real" active-open (with retry, ISN randomisation, options
selection) lives in a later chapter when we need outbound TCP.

### Why we don't handle out-of-order seqs

Real TCP receivers buffer out-of-order segments. ch22 only
needs the handshake; the next chapter wires receive-side queues.

## What's NOT here

- Data transfer (ch23).
- Retransmission + RTT (ch24).
- Send-queue + pump-on-ACK (ch25).
- Orderly close / FIN states (ch26).
- RST handling (ch27).
- Real ISN randomisation.
- TCP options beyond MSS (window scale, SACK, timestamps).
- Out-of-order receive buffering.

## Test discipline

| Axis             | Positive                                                                   | Negative                                              |
|------------------|----------------------------------------------------------------------------|-------------------------------------------------------|
| Listener         | `TCP listen : R1_re : port 80`                                             | -                                                     |
| Server FSM       | `SYN -> SYN_RECEIVED`, `SYN-ACK send`, `ACK -> ESTABLISHED`                | -                                                     |
| Client FSM       | `SYN send`, `SYN-ACK -> ESTABLISHED`, final `ACK send`                     | -                                                     |
| TCB dump         | `state=ESTABLISHED local=33333 remote=20.1.1.2:80 peer_mss=1460`           | -                                                     |
| Clean csum       | -                                                                          | NO `TCP recv : .* checksum invalid` on clean handshake|
| Regression       | ping + UDP still work                                                      | -                                                     |

## What's left

ch23: TCP data + cumulative ACK. ch24: retransmission + RTT.
ch25: send-queue + pump-on-ACK. ch26: orderly close (FIN states
+ TCB free). ch27: RST. ch28: packet capture. Then the
milestone goal: curl IN works.
