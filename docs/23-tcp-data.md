# ch23 - TCP data + cumulative ACK

## What landed

The receive handler now consumes data-bearing segments on
ESTABLISHED TCBs. After the handshake, an incoming PSH|ACK
with payload:

1. Sequence check: `seq == tcb->rcv_nxt`. Out-of-order drops
   with a log line (no reordering buffer in ch23; ch25 wires
   it).
2. Logs the receipt with a payload preview (first 32 bytes).
3. Bumps `tcb->rcv_nxt` by the data length (cumulative ACK
   position).
4. Emits a bare ACK carrying the new `rcv_nxt`.

`tcp_send_data(node, dst_ip, dst_port, payload, len)` walks the
TCB list for an ESTABLISHED entry matching the remote
`(ip, port)` and emits PSH|ACK. Caps payload at 150 bytes (the
ch9 L3 originate buffer limit).

CLI: `run node X tcp-send <ip> <dport> <text>`.

## End-to-end demo

```
samtcpip> config node R1_re tcp-listen 80
samtcpip> run node R0_re ping 20.1.1.2          ; warm ARP
samtcpip> run node R0_re tcp-syn 20.1.1.2 80    ; handshake
... [ESTABLISHED both sides]
samtcpip> run node R0_re tcp-send 20.1.1.2 80 hello-tcp
TCP send : R0_re : data seq=8193 len=9 to 20.1.1.2:80
TCP recv : R1_re : data seq=8193 len=9 `hello-tcp`
TCP send : R1_re : ACK seq=4097 ack=8202 to 20.1.1.1:33333
```

Cumulative ACK: `8202 == 8193 (seq) + 9 (len)`. The server
acknowledges everything up to byte 8202, telling R0 "I've
received bytes 8193 through 8201 inclusive."

## Design choices

### Why strict in-order only

ch23 ships the minimum that lets curl IN work for a static
HTTP request. Real wire MAY reorder; on a localhost-TAP wire
with no congestion it's exceedingly rare. ch25 adds the
reassembly buffer.

### Why a separate `send_bare_ack`

Used both by the handshake (`SYN-ACK -> ACK`) and the data
path (consume + ACK). The data path could piggyback the ACK
onto a return PSH if the server had data to send back; ch23
keeps it simple - the server doesn't originate data yet.

### Why 150-byte cap

The L3 originate path caps at 200. Header (20 IP + 20 TCP) is
40, plus options. 150 leaves margin and matches the UDP cap
from ch13. ch25's send-queue lifts this.

### Why we don't update snd_una

Real TCP tracks snd_una (oldest unacknowledged byte) and uses
it to free buffered data + drive retransmit. ch23 isn't doing
retransmit yet (that's ch24), and we don't buffer outgoing
data (that's ch25). So snd_una is implicit.

## What's NOT here

- Retransmission (ch24).
- Send-queue with pump-on-ACK (ch25).
- Window enforcement (later).
- Out-of-order reassembly buffer (ch25).
- Piggyback ACK on server-side response data.
- Data segments larger than 150 bytes (no fragmentation).

## Test discipline

| Axis             | Positive                                                      | Negative                                       |
|------------------|---------------------------------------------------------------|------------------------------------------------|
| Handshake first  | both sides reach ESTABLISHED                                  | -                                              |
| Client sends     | `TCP send : R0_re : data seq=8193 len=9 to 20.1.1.2:80`       | -                                              |
| Server receives  | `TCP recv : R1_re : data seq=8193 len=9 \`hello-tcp\``         | -                                              |
| Server ACKs      | `TCP send : R1_re : ACK seq=4097 ack=8202 to 20.1.1.1:33333`  | -                                              |
| Clean csum       | -                                                             | NO `TCP recv : .* checksum invalid`            |
| No TCB rejected  | `TCP send : R0_re : no ESTABLISHED TCB to`                    | -                                              |
| Regression       | ping + UDP                                                    | -                                              |

## What's left

ch24: retransmission + RTT (Jacobson SRTT/RTTVAR + Karn).
ch25: send-queue + pump-on-ACK. ch26: orderly close. ch27: RST.
ch28: pcap dump. Then the milestone goal.
