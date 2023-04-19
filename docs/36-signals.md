# ch36 - signal handling + clean shutdown

## What landed

`testapp.c` gains a `sigaction`-installed handler for `SIGINT`
and `SIGTERM`. On signal:
- Print a goodbye line + `fflush(stdout)` (stdout is
  block-buffered when redirected to a file).
- `tap_detach()` - drops the TAP fd cleanly so the kernel
  interface doesn't dangle past process death.
- `pcap_close_file()` - flushes + closes any active capture.
- `_exit(0)` - bypasses atexit handlers (none today) and
  exits with success.

Handlers installed AFTER `nwcli_install` so the handler can
safely reference any module state.

## End-to-end demo

```
$ ./testapp &
samtcpip>
$ kill -INT <PID>

Received signal 2 - shutting down cleanly
PCAP close       ; if a capture was active
TAP detach       ; if a TAP was attached
$
```

Exit code 0. No leaked TAP. No truncated pcap.

## Design choices

### Why `_exit` not `exit`

`exit(3)` flushes stdio + runs atexit handlers. We don't have
atexit handlers and we don't want to do the stdio dance twice
(we already fflush). `_exit(2)` skips both, ends the process
immediately. Cleaner.

### Why fflush before _exit

When stdout is redirected to a file (CI runs, tests, log piping),
it switches to block-buffered. Without `fflush`, the printed
goodbye line stays in libc's buffer and never reaches the file
before `_exit` kills the process.

### Why handle BOTH SIGINT and SIGTERM

SIGINT is Ctrl-C from a terminal. SIGTERM is the default for
`kill` and `systemctl stop`. A well-behaved daemon answers both.

### Why no SIGHUP

Real daemons reload config on SIGHUP. We have no config to
reload. If a future "reread settings.json" chapter ships, we
add the handler then.

### Why install_signal_handlers is called AFTER nwcli_install

So the handler can use the global state nwcli_install set up
(g_topo, the registered handlers, etc) if it ever needs to.
Today it doesn't, but the ordering is the safe one.

## What's NOT here

- SIGHUP reload.
- SIGUSR1 / SIGUSR2 for runtime knobs.
- Restart-on-signal (some daemons do this).
- core_pattern integration for crash dumps.
- Async-signal-safe printf (the library's printf is NOT signal-
  safe; we get away with it because the test scenarios are
  simple. A future polish chapter could write directly to fd 1
  via write(2)).

## Test discipline

| Axis           | Positive                                                |
|----------------|---------------------------------------------------------|
| SIGINT handler | `Received signal 2 - shutting down cleanly`             |
| SIGTERM handler| `Received signal 15 - shutting down cleanly`            |
| Exit code      | 0 in both cases                                         |
| Ping regression| `Ping reply : R0_re : seq=3 from 20.1.1.2`              |

The test uses a fifo to keep stdin open (the CLI's REPL exits
on EOF; without the fifo the process self-exits before we
can signal it).

## What's left

ch37: log level discipline (debug / info / warn / error).
ch38: Milestone 5 sign-off.
