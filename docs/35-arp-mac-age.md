# ch35 - ARP + MAC table aging

Milestone 5 begins. Operational hygiene. The stack now expires
idle ARP and MAC entries so a long-running process doesn't leak
state on every host it has ever seen.

## What landed

- `ArpEntry` and `MacTableEntry` grow a `last_seen_ms` field.
- Both are stamped on install + refreshed on every lookup hit
  (so entries in active use never age out).
- `arp_age(arp_table, threshold_ms)` walks + removes entries
  whose `(now - last_seen_ms) >= threshold_ms`. Returns count
  removed.
- `mac_age(mac_table, threshold_ms)` is symmetric.
- New CLIs: `run node X arp-age <ms>`, `run node X mac-age <ms>`.

## End-to-end demo

```
samtcpip> run node R0_re ping 20.1.1.2
... ARP cache populated for 20.1.1.2

samtcpip> run node R0_re arp-age 100000
ARP age : R0_re : removed 0 stale entry(s) (threshold=100000ms)
   ; fresh entry survives

samtcpip> run node R0_re arp-age 1
ARP age : 20.1.1.2 : timeout age=219ms (threshold=1ms)
ARP age : R0_re : removed 1 stale entry(s) (threshold=1ms)
   ; with a 1ms threshold, anything older than the moment ages out
```

## Design choices

### Why refresh on lookup hit

Real ARP doesn't age entries that are actively used. If the host
keeps talking to a peer, the cache stays fresh. Lookups in the
recv path bump `last_seen_ms`; without that, every long-lived
conversation would lose its cache entries periodically.

### Why no background aging thread

Same call as the archive-era aging chapters: manual CLI for
test determinism, background tick when a future "unified ticker"
chapter ships. The threshold value is the only thing a periodic
tick would change.

### Why both inline `static long now_ms` helpers (one per file)

`layer2.c` and `l2switch.c` each need a monotonic ms clock. We
could expose one in utils, but two 4-line copies are fine for
the scope. A future utility chapter could consolidate.

### Why aging doesn't notify higher layers

If TCP cares (e.g. an open connection's peer ARP entry just got
aged), the next L3 emit would just re-ARP and rebuild the cache.
No notification needed.

## What's NOT here

- Background ticker.
- Per-Node configurable default thresholds.
- Aging metrics / stats counters.
- Refresh on USE separately from refresh on LOOKUP (we only do
  the latter; OK because every send walks the lookup path).
- ARP cache size cap with LRU eviction.

## Test discipline

| Axis              | Positive                                                                |
|-------------------|-------------------------------------------------------------------------|
| Fresh survives    | `ARP age : R0_re : removed 0 stale entry(s) (threshold=100000ms)`       |
| Stale ages out    | `ARP age : R0_re : removed 1 stale entry(s) (threshold=1ms)`            |
| Names the IP      | `ARP age : 20.1.1.2 : timeout age=`                                     |
| Post-age clean    | post-age `show node arp` does NOT include the aged IP                    |
| Re-ping refills   | `show node arp` lists the IP again after a fresh ping                   |

## What's left

ch36: signal handling + clean shutdown (SIGINT closes TAP +
flushes pcap + exits cleanly).
ch37: log level discipline.
ch38: Milestone 5 sign-off.
