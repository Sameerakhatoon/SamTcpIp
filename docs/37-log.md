# ch37 - log level discipline

## What landed

Two tiny files - `log.h` + `log.c` - giving the codebase a
filterable log path.

Four levels, low to high:
- `LOG_DEBUG` - chatty per-packet wire dumps
- `LOG_INFO`  - one-line lifecycle events
- `LOG_WARN`  - recoverable anomaly
- `LOG_ERROR` - giving up on this operation

`g_log_level` is the global threshold. Messages below it are
silently dropped at the macro site (the `if (...)` short-
circuits before any printf work).

Default level is INFO.

Two new CLI verbs:
- `run log-level <name>` - set the filter (debug|info|warn|error)
- `run log-test`         - emit one line at each level (smoke test)

## Why now

ch35 added aging chatter. ch28 added pcap chatter. Future
chapters (DHCP polling, RIP timers, ARP retries) will be even
chattier. A `make demo` log that's 80% routine becomes useless.

LOG_DEBUG gives that chatter a kill switch. INFO stays loud
because the user wants to see "ping reply seq=3" in normal use.

## Why I didn't rewrite the existing printf() calls

Hundreds of them. Touching them all would dwarf this chapter
and risk breaking parsers in tests that grep stdout. Instead:

- Treat the existing printfs as locked-in at INFO.
- NEW code uses `LOG_*()`.
- The old test suite keeps passing unmodified.

This is a one-way ratchet: any new chapter introducing log
spew has to use `LOG_DEBUG` or argue otherwise.

## Why the macros take `...`

So callers write naturally:

```c
LOG_DEBUG("arp: refresh %u.%u.%u.%u via %s\n", a, b, c, d, oif);
```

instead of `LOG_DEBUG("...", buf)`. The cost is the `[D] `
prefix lands in a separate printf - acceptable because the
macros also fflush, so the two writes never interleave.

## End-to-end demo

```
samtcpip> run log-test
[I] info-line
[W] warn-line
[E] error-line
samtcpip> run log-level warn
log-level : set to warn
samtcpip> run log-test
[W] warn-line
[E] error-line
samtcpip> run log-level debug
log-level : set to debug
samtcpip> run log-test
[D] debug-line
[I] info-line
[W] warn-line
[E] error-line
samtcpip> run log-level lolwut
log-level : unknown `lolwut` (expected debug|info|warn|error)
```

## What's NOT here (on purpose)

- Per-module levels (e.g. `log-level arp=debug`). Would need a
  table; level checks become non-trivial. Future polish.
- File / line / timestamp prefix. Easy to add - intentionally
  deferred so the format stays grep-friendly today.
- Bulk migration of legacy printfs. Per above.
- Routing to a file. `./testapp 2>&1 | tee file.log` works.

## Test discipline

`tests/37-log.sh` verifies four blocks of `run log-test`
output under four filter settings:

| Level set | D | I | W | E |
|-----------|---|---|---|---|
| info (default) | -- | yes | yes | yes |
| warn      | -- | -- | yes | yes |
| debug     | yes | yes | yes | yes |
| error     | -- | -- | -- | yes |

Plus: unknown-name input is rejected with a helpful message.

## What's left

ch38: Milestone 5 sign-off (operational hygiene done).
