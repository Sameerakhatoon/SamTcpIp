# ch39 - PMTUD path cache + ICMP Frag-Needed receive

## What landed

Three pieces:

1. **`Layer3/pmtu.{c,h}`** - a 16-slot per-destination MTU cache.
   `pmtu_install(dst, mtu)` stores; `pmtu_lookup(dst)` returns the
   cached MTU or 0; `pmtu_clear(0)` wipes all.

2. **Originate path consults the cache.**
   `demote_packet_to_layer3` now picks per-fragment payload as
   `min(IP_MAX_FRAG_PAYLOAD, cached_mtu - sizeof(IpHdr))`. Default
   behaviour (no entry): unchanged 100-byte budget. So the cache
   can only make us send SMALLER fragments. That matches RFC 1191's
   "discovery shrinks, never grows".

3. **`Layer5/ping.c` parses ICMP Type 3 Code 4** ("Fragmentation
   Needed, DF set") and installs the carried next-hop MTU into the
   cache, keyed by the original packet's destination IP (read from
   the original IP header embedded in the ICMP body per RFC 792).

## CLI

```
run pmtu set <dst-ip> <mtu>   # inject / override an entry
run pmtu show                 # dump the cache
run pmtu clear                # wipe all
```

The `set` verb is the test hook - production paths populate the
cache via the ICMP receive in step 3.

## End-to-end demo

```
samtcpip> run node R0_re udp-big 20.1.1.2 250
IP frag emit : R0_re : id=5 off=0 len=96 MF=1
IP frag emit : R0_re : id=5 off=96 len=96 MF=1
IP frag emit : R0_re : id=5 off=192 len=66 MF=0

samtcpip> run pmtu set 20.1.1.2 60
PMTU install : dst=20.1.1.2 mtu=60

samtcpip> run node R0_re udp-big 20.1.1.2 250
IP frag emit : R0_re : id=10 off=0 len=40 MF=1
IP frag emit : R0_re : id=10 off=40 len=40 MF=1
... (7 fragments total)

samtcpip> run pmtu clear
PMTU clear all
samtcpip> run node R0_re udp-big 20.1.1.2 250
IP frag emit : R0_re : id=16 off=0 len=96 MF=1
IP frag emit : R0_re : id=16 off=96 len=96 MF=1
IP frag emit : R0_re : id=16 off=192 len=66 MF=0
```

3 fragments -> 7 fragments -> 3 fragments. The cache works.

## Why a per-destination cache, not per-route or per-interface

RFC 1191 explicitly says PMTU is a path property keyed by the
destination IP. The narrowest link in a path doesn't have to be
on the egress interface - it might be three hops downstream. A
per-route or per-interface MTU table would lie about that.

## What I deliberately did NOT add

- **Wire emit of Frag-Needed on forwarding.** A router that sees a
  DF=1 packet larger than the next-hop MTU is supposed to drop it
  and send Type 3 Code 4 back. We never set DF=1 on originate
  (RFC 1191 says you SHOULD; we don't because our originate already
  fragments by IP_MAX_FRAG_PAYLOAD and there's no real router
  between us and the dst to discover further shrinkage). The receive
  side IS wired, so if any real upstream router on a real wire ever
  sends one to us, we cache it correctly.
- **Cache aging.** RFC 1191 sec 6.3 says discovered values should
  be re-tried periodically (path may have changed for the better).
  Not implemented. A 16-slot cache that doesn't age is fine for
  the test rig.
- **Per-socket integration.** Real kernels expose the cached MTU to
  setsockopt(IP_MTU). We have no sockets API.

## Test discipline

`tests/39-pmtu.sh` runs the three-burst pattern above and asserts:

| Phase                | Expected fragment count for 250-byte UDP |
|----------------------|------------------------------------------|
| no cache (default)   | 3                                        |
| `pmtu set dst 60`    | >= 6 (we get 7)                          |
| `pmtu clear`         | 3                                        |

Plus the install / clear lines appear in stdout.

## What's left

ch40: TCP congestion control (cwnd + slow-start)
ch41: TCP real peer-window enforcement
ch42: Milestone 4 sign-off
