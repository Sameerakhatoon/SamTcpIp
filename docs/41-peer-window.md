# ch41 - TCP real peer-window enforcement

## What landed

`tcp_send_data` now gates outbound segments on the peer's
advertised window. Before this chapter the function would
emit any payload up to a 150-byte hardcoded cap regardless
of how much room the receiver said it had.

The gate, expressed in plain English:

```
in_flight  = snd_nxt - snd_una                   # bytes sent, not yet ACKed
allowed    = min(cwnd, peer_window) - in_flight
if payload_size > allowed:  refuse
```

`peer_window` was added in ch40 alongside the cwnd plumbing; ch41
is the chapter where it actually does something.

## Where peer_window comes from

Three points update it:

1. **SYN-ACK receive (client side):** the listener's SYN-ACK
   carries its window. We snapshot it on the SYN_SENT ->
   ESTABLISHED transition.
2. **ACK that completes handshake (server side):** the third
   leg's window field updates our peer_window on the
   SYN_RECEIVED -> ESTABLISHED transition.
3. **Pure ACK in ESTABLISHED:** every bare ACK carries the
   peer's current window. We resnapshot. If the value changes
   we log it.

## tcp-rwnd CLI

```
samtcpip> run tcp-rwnd <bytes>
TCP rwnd : set to <bytes> (will advertise on next segment)
```

Sets the global window value we advertise in every outbound
segment. Default 1024 (the test rig's historical value).

Real impls compute this per-TCB from the receive-buffer
free space. We are deliberately leaving that for a future
chapter; a global knob is enough to prove the gate is real.

## tcp-send-big CLI

```
run node X tcp-send-big <ip> <port> <bytes>
```

Sends N bytes of filler. The existing `tcp-send` takes a
single text token (so its useful range is "hello"-sized).
This new verb makes it easy to probe the gate.

## End-to-end demo

```
samtcpip> run tcp-rwnd 100                # peer will tell us its window is 100
samtcpip> config node R1_re tcp-listen 80
samtcpip> run node R0_re ping 20.1.1.2    # warm ARP
samtcpip> run node R0_re tcp-syn 20.1.1.2 80
TCP cwnd : R0_re : init cwnd=1460 ssthresh=65535 peer_win=100

samtcpip> run node R0_re tcp-send-big 20.1.1.2 80 200
TCP send : R0_re : window-blocked in_flight=0 + len=200 > min(cwnd=1460, peer_win=100)

samtcpip> run node R0_re tcp-send-big 20.1.1.2 80 50
TCP send : R0_re : data seq=8193 len=50 to 20.1.1.2:80
TCP send : R1_re : ACK seq=4097 ack=8243 to 20.1.1.1:33333
TCP cwnd : R0_re : slow-start ack=8243 acked=50 cwnd=2920 ssthresh=65535
```

Same TCB, two sends, same cwnd (1460). The 200 is refused, the
50 goes through. The gate works.

## Why min(cwnd, peer_window) and not just one

- `peer_window` is what the receiver said it can buffer.
  Sending more would force the receiver to drop or buffer-bloat.
- `cwnd` is what we estimate the path can carry without loss.
  Sending more would queue at a router and provoke loss.

Both are upper bounds. Send less than the lower of them.

## What I deliberately did NOT add

- **Per-TCB rwnd from a real receive buffer.** Global knob is
  enough to prove the gate. Real impls track per-TCB.
- **Send-queue / drain-on-ACK.** Today: oversized send is
  refused (return false). Real impls queue the bytes and emit
  as the window opens. Per PLAN.md (and the cwnd doc) send-
  queue is its own deferral.
- **Window scaling (RFC 7323).** No SYN option negotiated, so
  max advertised window is 65535. Fine for our 4-byte test
  sends.
- **Zero-window probing.** If the peer advertises 0, we'd
  refuse forever. Real impls fire persist-timer probes. We
  don't (deferred).
- **Silly-window-syndrome avoidance.** Nagle / Clark. Not here.

## Test discipline

`tests/41-peer-window.sh`:

| Assertion                                       | Expected             |
|-------------------------------------------------|----------------------|
| rwnd CLI prints set-to                          | yes                  |
| client TCB picks up peer_win=100 on ESTABLISHED | yes                  |
| 200-byte send blocked (200 > 100)               | window-blocked log   |
| 50-byte send goes through                       | data seq=... len=50  |
| Regression: default 1024 + 5-byte send works    | yes                  |
| Regression: default peer_win=1024 on init       | yes                  |

## What's left

ch42: Milestone 4 sign-off (real-wire robustness done).
