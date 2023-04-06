# ch28 - packet capture facility (.pcap)

Standard libpcap format (magic `0xa1b2c3d4`, LINKTYPE_ETHERNET).
Every frame that crosses `send_pkt_out` or `pkt_receive` lands
in the active capture file. Single global sink with a mutex.

CLI: `run pcap start <file>` / `run pcap stop`.

Output opens directly in tcpdump / wireshark.

## What landed

- `pcap.{h,c}` at project root.
- `pcap_open_file(path)` writes the 24-byte global header.
- `pcap_close_file()` closes.
- `pcap_dump_frame(buf, len)` writes a 16-byte record header
  (`ts_sec`, `ts_usec`, `incl_len`, `orig_len`) + frame bytes.
- Hooks in `comm.c::send_pkt_out` (egress) and
  `comm.c::pkt_receive` (ingress).

## End-to-end demo

```
samtcpip> run pcap start /tmp/test.pcap
PCAP open : /tmp/test.pcap
samtcpip> run node R0_re ping 20.1.1.2
Ping reply : R0_re : seq=3 from 20.1.1.2
samtcpip> run pcap stop
PCAP close

$ tcpdump -r /tmp/test.pcap
ARP, Request who-has 20.1.1.2 tell 20.1.1.1, length 28
ARP, Reply 20.1.1.2 is-at ..., length 28
IP 20.1.1.1 > 20.1.1.2: ICMP echo request, id ..., seq 1
IP 20.1.1.2 > 20.1.1.1: ICMP echo reply, id ..., seq 1
...
```

## Design choices

### Single global sink

One capture file at a time. Multi-sink (per-interface, per-node)
would need a richer API; not on the curl-needle.

### Mutex around all access

`pcap_dump_frame` is called from both recv threads (UDP loopback
recv + TAP recv via the ch17 ingress lock; egress from any
caller). Without the mutex, interleaved writes corrupt records.

### Why us-resolution timestamps

`gettimeofday()` is portable + universal. `clock_gettime` with
`CLOCK_MONOTONIC` would be nicer but isn't libpcap's
expectation - the magic `0xa1b2c3d4` says us-resolution wall
clock. Wireshark interprets accordingly.

### snaplen = 65535

Capture full frames. Not bandwidth-constrained at our scale.

## What's NOT here

- Per-interface filter (BPF expressions).
- Capture rotation by size or time.
- Per-Node sinks.
- ns-resolution timestamps (magic `0xa1b23c4d`).
- Direction tagging (ingress vs egress) in the record.

## Test discipline

| Axis            | Positive                                          | Negative                                              |
|-----------------|---------------------------------------------------|-------------------------------------------------------|
| Open / close    | `PCAP open : <file>` + `PCAP close`               | -                                                     |
| File exists     | stat -c %s >= 100                                  | -                                                     |
| Magic header    | first 4 bytes = `d4 c3 b2 a1` (LE 0xa1b2c3d4)     | -                                                     |
| Ping regression | `Ping reply : R0_re : seq=3 from 20.1.1.2`        | -                                                     |
| UDP regression  | `UDP printer : R0_re : port 12345 from 20.1.1.2:7`| -                                                     |

## What's left

Phase 0 of Milestone 2 done. Plumbing complete:
- TCP handshake (ch22)
- TCP data + ACK (ch23)
- TCP orderly close (ch26)
- TCP RST (ch27)
- pcap dump (ch28)

Skipped (PLAN.md rule 1): ch24 rtx + ch25 send-queue. Wire-quality polish for lossy networks; deferrable.

Milestone 2 goal chapter: under root, attach TAP + configure +
listen + `curl http://<our-tap-ip>/` returns "hello" from a
tiny in-stack HTTP responder.
