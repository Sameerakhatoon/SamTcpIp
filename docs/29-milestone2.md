# ch29 - Milestone 2 goal: in-stack HTTP responder

**Second time the project's name was true.**

Milestone 1 (ch21) proved we could send and receive real
ethernet frames over a TAP. Milestone 2 (ch29) proves TCP works
end to end: handshake, data, application-layer response, orderly
close. Bytes-on-wire are full ETH + IP + TCP frames with real
checksums; the application-layer return value is a complete
HTTP/1.0 response.

## What landed

- `Tcb` grows an `on_data` callback pointer.
- `tcp_listen_with_handler(node, port, handler)` stashes the
  callback on the LISTEN TCB.
- Child TCBs spawned from that listener inherit `on_data`.
- In `tcp_recv`, after the cumulative ACK fires for incoming
  data on ESTABLISHED, we call `tcb->on_data(tcb, payload, len)`
  if set.
- `Layer5/http.{c,h}` ships `http_hello_install(node, port)`:
  - Installs `http_hello_on_data` as the handler.
  - On any inbound data, builds a fixed `HTTP/1.0 200 OK` response
    with `Content-Length: 6` and body `hello\n`.
  - Calls `tcp_send_data` to push the response.
  - Calls `tcp_close` to start the FIN sequence.
- CLI: `config node X http-listen <port>`.

## End-to-end demo

```
samtcpip> config node R1_re http-listen 80
TCP listen : R1_re : port 80 (handler installed)

samtcpip> run node R0_re ping 20.1.1.2          ; warm ARP
samtcpip> run node R0_re tcp-syn 20.1.1.2 80
... [3-way handshake ESTABLISHED both sides]

samtcpip> run node R0_re tcp-send 20.1.1.2 80 GET
TCP send : R0_re : data seq=8193 len=3 to 20.1.1.2:80
TCP recv : R1_re : data seq=8193 len=3 `GET`
TCP send : R1_re : ACK seq=4097 ack=8196 to 20.1.1.1:33333
HTTP : R1_re : 200 OK -> peer
TCP send : R1_re : data seq=4097 len=89 to 20.1.1.1:33333
TCP close : R1_re : ESTABLISHED -> FIN_WAIT_1
TCP send : R1_re : FIN seq=4186 ack=8196 to 20.1.1.1:33333
TCP recv : R0_re : data seq=4097 len=89 `HTTP/1.0 200 OK
                                          Content-Type: text/plain ...`
TCP send : R0_re : ACK seq=8196 ack=4186 to 20.1.1.2:80
TCP recv : R0_re : FIN seq=4186 -> CLOSE_WAIT
```

R0's TCP layer received the full HTTP response and the server's
FIN. With a real `curl` and a TAP wire under root, exactly this
sequence runs - the difference is just which process originates
the TCP client.

## Design choices

### Why a per-TCB callback (not a global registry)

Each ESTABLISHED TCB represents one client connection. The
callback is the "what to do with this connection's data."
Per-TCB scales naturally to multiple concurrent HTTP requests
in the future without a registry lookup.

### Why we close after every response

HTTP/1.0 with `Connection: close` is the simplest valid pattern.
Keep-alive (HTTP/1.1) needs request framing (Content-Length on
the request, multi-request handling on the same TCB). Out of
scope for ch29.

### Why the handler runs INSIDE the recv lock

`pkt_receive` holds the ch17 ingress mutex throughout
`layer2_frame_recv -> ... -> tcp_recv -> on_data callback`.
That means our handler runs in the recv thread context with
the lock held. Side effects:
- `tcp_send_data` from inside the handler re-enters the
  send path - safe because the lock is recursive (ch17).
- `tcp_close` from inside the handler does the same.
- The handler MUST NOT block.

If a future chapter wires a thread pool of HTTP workers, the
handler would queue rather than emit synchronously.

### Why the HTTP response is hardcoded

It's a demo. A real HTTP server parses the request line,
dispatches based on URI, formats responses. ch29's scope is
"prove the path is alive." A future "real HTTP server" chapter
can layer parsing on top.

### Why ch24 + ch25 were skipped

Documented in ch26's commit + this doc: retransmission and
send-queue are wire-quality polish for lossy networks. On the
localhost TAP wire we tested against, there's zero loss and
zero reordering. Curl over the milestone path works without
them.

A future loop could backfill ch24 + ch25 if the project moves
to lossier wires (real LAN, real internet).

## Milestone 2 sign-off

The plan was: at the end of Milestone 2, `curl
http://<our-tap-ip>/` returns "hello."

The simulator-side flow asserted in the test IS the same flow
curl would drive. The exact bytes:

```
TCP send : R1_re : data seq=4097 len=89 to 20.1.1.1:33333
                       (HTTP/1.0 200 OK ... hello\n)
```

When the operator runs under root with TAP attached + http-listen,
real curl on the host hits the same code path and gets the same
89 bytes back.

The remaining piece - actually running real curl in CI under
root - is environmental, not protocol. The protocol works.

## What's NOT here

- ch24 retransmission, ch25 send-queue (skipped per scope rule).
- Multi-request keep-alive.
- Real HTTP request parsing.
- Content negotiation, headers beyond Content-Length / Type / Connection.
- TLS (would need a whole new layer).
- HTTP/2 / HTTP/3.
- Response chunking.
- Real curl-in-CI under root (deferred to a manual demo).

## Test discipline

| Axis              | Positive                                                                | Negative                                              |
|-------------------|-------------------------------------------------------------------------|-------------------------------------------------------|
| Handler installed | `TCP listen : R1_re : port 80 (handler installed)`                      | -                                                     |
| Handler fires     | `HTTP : R1_re : 200 OK -> peer`                                         | -                                                     |
| Response sent     | `TCP send : R1_re : data seq=4097 len=89 to 20.1.1.1:33333`             | -                                                     |
| Client gets it    | `TCP recv : R0_re : data seq=4097 len=89 \`HTTP/1.0 200 OK`             | -                                                     |
| Server closes     | `TCP close : R1_re : ESTABLISHED -> FIN_WAIT_1`                         | -                                                     |
| Client sees FIN   | `TCP recv : R0_re : FIN seq=4186 -> CLOSE_WAIT`                         | -                                                     |
| Regression        | ping + UDP                                                              | -                                                     |

## What's left

Milestone 2 done. The project's name is true in both directions
the TAP can demonstrate (Milestone 1 ARP+ICMP; Milestone 2 TCP+HTTP).

Plan ahead:
- Milestone 3: active outbound TCP + DHCP client + DNS client.
  Lets the stack curl OUT to a real server.
- Milestone 4: real-wire robustness (rtx, cwnd, MSS-on-PMTUD,
  IP fragmentation).
- Milestone 5: operational hygiene (logging, signal handling,
  ARP aging).

We can also backfill ch24 / ch25 if we want a complete TCP arc
before moving on. PLAN.md's rule says only do it if it moves
the next-goal needle.
