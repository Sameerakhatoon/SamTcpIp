# ch38 - Milestone 5 sign-off: operational hygiene

## What this chapter is

A cap chapter. No new wire-format code. It declares Milestone 5
done by running a single end-to-end test that combines all three
operational-hygiene features from this run:

| Feature                | Chapter | What it gives us                         |
|------------------------|---------|------------------------------------------|
| ARP + MAC aging        | ch35    | bounded memory under long run            |
| Clean shutdown         | ch36    | TAP/pcap closed properly on signal       |
| Log level discipline   | ch37    | shut up the chatter; keep ping visible   |

## What "operational hygiene" actually means

PLAN.md frames Milestone 5 as: *"stack is something a person
could actually run."*

Concretely, before M5:
- Running `./testapp` for hours grew ARP and MAC tables without
  bound.
- Ctrl-C left the TAP interface dangling - kernel state for a
  process that no longer existed.
- Every packet hit `printf`, so a real curl run buried any
  interesting line under wire dumps.

After ch35-37 (and verified by this sign-off):
- Aging knobs exist and the CLI exposes them.
- SIGINT and SIGTERM both trigger a `tap_detach` + `pcap_close`
  before `_exit(0)`.
- Default log level INFO keeps useful messages visible; `run
  log-level warn` hides per-packet chatter.

## The sign-off test

`tests/38-milestone5.sh` opens a fifo'd stdin and runs:

1. `run log-level warn`   - shut up the chatter
2. `run node R0_re ping 20.1.1.2`  - regression: ping still works
3. `run node R0_re arp age 1000`   - aging knob present
4. `run log-test`         - filter actually filters
5. `kill -TERM $PID`      - clean shutdown

Then verifies the captured stdout shows:

- `[W] warn-line` and `[E] error-line` but NO `[I] info-line`
  (proves the WARN filter)
- `Ping reply` (proves stack still works at WARN level)
- `Received signal 15` + `shutting down cleanly` (proves
  SIGTERM caught)

## Why not also test `arp age` shrinking the table

Aging is wall-clock driven and the fifo-based test scaffold
can't sleep 30 seconds without flaking under CI. ch35's own
test covers the actual mechanic; this sign-off proves the
CLI is wired and the program doesn't crash.

## What's NOT in Milestone 5

Things that PLAN.md flagged as out-of-scope and stay that way:
- Real syslog / journald integration
- Per-module log levels
- Hot config reload (SIGHUP)
- Async-signal-safe printing
- `prometheus_exporter`-style metrics endpoint

Each is a polish chapter, not an MVP gate.

## State of the project after ch38

Five milestones, all hit:

```
M1 ch21   on the wire             host pings us, we ping host
M2 ch29   TCP passive             curl OUT works against our HTTP responder
M3 ch33   TCP active + autoconfig  curl from inside our stack works
M4 ch34   real-wire robustness    IP frag/reassembly (cwnd/pmtud deferred)
M5 ch38   operational hygiene     bounded growth, clean exit, filterable logs
```

The phrase "userspace TCP/IP stack" is now true without
qualifiers. Both directions of `curl` work. The stack survives
a real network's behaviour. It exits cleanly. It can be told
to shut up.

## What's still ahead (optional)

The PLAN.md "out of scope" list still applies; any of those
becomes a Phase 6+ run if motivated. Most-likely-next-targets,
ranked by curl-needle impact-per-chapter:

1. TCP retransmission timer (today RST-on-drop, never retx)
2. send-queue + window-aware emit (today: send-and-pray)
3. fragment overlap detection (today trust the wire)
4. ICMP error receive (today only emit)

None of these are gated by M5; M5 is signed off as-is.
