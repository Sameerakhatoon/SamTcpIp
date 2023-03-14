# ch15 - TAP recv thread wired into pkt_receive

ch14 shipped open/close primitives. ch15 makes TAP actually
**useful**. A background recv thread reads from the TAP fd and
feeds every frame into `pkt_receive(node, iif, ...)`. The
kernel side of the TAP is now in conversation with our L2
ingress.

The simulator's UDP-loopback wire is unchanged - it still
handles inter-Node traffic. ch15 ADDS a second ingress path
that takes real Linux frames into the same pkt_receive. ch16
will add the symmetric egress hook.

## What landed

### tap_attach / tap_detach

```c
int  tap_attach(Node* node, const char* ifname, const char* iif_name);
void tap_detach(void);
```

`tap_attach`:
1. Calls `tap_open(ifname)` (ch14).
2. Looks up `iif_name` on `node` to get the `Interface*` the
   recv thread will pass to `pkt_receive`.
3. Spawns a pthread running `tap_recv_thread`.
4. Logs `TAP attach : <ifname> -> <node>/<iif> fd=<n>`.

`tap_detach`:
1. Sets an `atomic_int g_tap_stop` flag.
2. `pthread_join` on the recv thread.
3. Closes the fd.
4. Logs `TAP detach`.

### The recv thread

```c
static void* tap_recv_thread(void* arg){
    while(!atomic_load(&g_tap_stop)){
        select(g_tap_fd + 1, &rfds, ..., timeout=100ms);
        if(rc == 0) continue;
        long n = tap_recv_raw(g_tap_fd, buf, sizeof(buf));
        pkt_receive(g_tap_node, g_tap_iif, (char*)buf, n);
    }
}
```

The 100ms `select` gate is the trick: it lets `tap_detach`
flip the stop flag and have the thread notice within 100ms,
versus blocking forever in `read()`.

Frames pass through with no transformation. `IFF_NO_PI` means
the buffer is exactly the wire frame; `pkt_receive` expects
exactly that. No aux header to strip (the simulator's UDP-
loopback path strips a 16-byte iface-name prefix; the TAP
path doesn't have one).

### CLI

```
run tap attach <node> <ifname> <iif>
run tap detach
```

`run tap open` / `run tap close` from ch14 still exist as
standalone primitives for testing. The new verbs are the
integration layer.

### Threading + locking

This is the first chapter that adds a second thread that
calls into the simulator's core. Per PLAN.md the event-loop
+ locking model is ch17; ch15 takes the smallest possible
step toward it:

- The recv thread reads `g_tap_node` / `g_tap_iif` AFTER
  `tap_attach` has set them. The CLI dispatcher waits for
  `pthread_create` to return before its handler exits, so the
  recv thread always sees consistent values.
- `pkt_receive` is whatever the existing pkt_receive is. It
  walks L2 dispatch; that path predates ch15. If it has
  thread-safety issues with multiple recv threads, ch17 will
  surface and fix them.

For ch15: one recv thread, no concurrency hazards in our test
matrix. Sufficient until ch17.

## End-to-end demo (root)

```
samtcpip> run tap attach R0_re samtap0 eth0/0
TAP opened : ifname=samtap0 fd=4
TAP attach : samtap0 -> R0_re/eth0/0 fd=4
TAP recv thread started

samtcpip> run tap detach
TAP recv thread exited
TAP closed
TAP detach
```

A second terminal can `sudo ip link set up dev samtap0` and
`sudo ip addr add 10.0.0.1/24 dev samtap0`. Any frame the
kernel sends out the TAP (ARP, ping, broadcast) lands in the
recv thread's read loop, gets logged as
`TAP recv : N bytes on R0_re/eth0/0`, then enters
`pkt_receive(R0_re, eth0/0, buf, n)`.

The simulator's L2 will probably FCS-reject, drop, or warn
about most of these because no IP is configured on R0_re's
eth0/0 yet. ch18 fixes that. ch15 is "the thread exists and
fires."

## End-to-end demo (non-root)

```
samtcpip> run tap attach R0_re samtap0 eth0/0
TAP open failed : /dev/net/tun : ... or
TAP ioctl TUNSETIFF failed : Operation not permitted (errno=1)
```

`tap_attach` returns -1 without starting a thread. Same
diagnostic as ch14, same test branch.

## Design choices

### Why 100ms select gate

Real Linux kernels can block a `read(tun_fd)` for arbitrary
durations. If `tap_detach` set the stop flag but the thread
was inside a blocking `read`, detach would hang forever.

The alternatives:
- `pthread_cancel` - works but brittle (the thread might be
  inside libc which doesn't tolerate cancellation cleanly).
- Non-blocking fd + tight poll - high CPU.
- `select` with timeout - clean, simple, lets the thread
  rotate through the stop-flag check.

100ms is fine for our latency budget. A real-time stack would
want shorter; we're not real-time.

### Why one recv thread (not one per fd)

We have one TAP fd. One thread suffices. The simulator's
existing UDP-loopback recv thread is a separate beast handling
the Node sockets; ch15 does NOT touch it.

### Why `atomic_int` for the stop flag

`bool` would work on x86 because of the memory model, but
atomic is portable + clear about intent. The detach side
writes `1`; the recv thread reads in its loop. No locks
needed.

### Why we don't bring the interface UP from inside our code

`ioctl(SIOCSIFFLAGS, IFF_UP)` requires `CAP_NET_ADMIN`. We
have that (we just used it for TUNSETIFF). We could absolutely
bring the interface up here. But:

- ch15's scope is the recv pipeline.
- The interface needs an IP to receive useful frames; assigning
  the IP is ch18's job.
- For ch15 tests, the interface doesn't need to be up - the
  recv thread tests that it can SPAWN and CLEANLY EXIT.

ch16 brings the interface up + sets the IP.

### Why tap_attach takes both node AND iif_name

The Node is the userspace stack's home (R0_re in our test
topology, "the one Node" per PLAN.md rule 4 once we collapse).
The interface within that Node is which logical `eth0/X` the
TAP plays the role of. `pkt_receive` needs both because L2
dispatch reads per-interface state (MAC, IP).

For a single-Node userspace stack, the iif could default to
`eth0/0`. We keep both args explicit for clarity.

### Why we keep `run tap open` / `run tap close` from ch14

They exercise the raw primitive without the thread machinery.
Useful for debugging "is the TAP layer broken, or the thread
layer?". Costs nothing to keep them.

### Why no send-from-CLI verb yet

`tap_send_raw` is the wrapper. A `run tap send-hex <bytes>`
CLI would let an operator inject a raw frame to test the
recv-side dispatch. We don't need it yet; ch16 wires
`send_pkt_out -> TAP` which is the natural send-test path.

## What's NOT here

- Bringing the interface up (ch16+).
- Assigning an IP (ch18).
- Send hook (ch16: `send_pkt_out` -> TAP fd).
- The event-loop + locking-model chapter (ch17).
- Multi-TAP support. Single static `g_tap_fd`.
- Per-frame stats. The recv thread logs every frame, then
  enters L2 dispatch; counters come with ch68-equivalent.
- Frame filtering (BPF / promiscuous toggles).
- Graceful handling of TAP-disappeared mid-run (someone
  `ip link delete samtap0` while we're attached).

## Test discipline

| Axis              | Positive (root)                                      | Positive (non-root)                                       | Negative                                              |
|-------------------|------------------------------------------------------|-----------------------------------------------------------|-------------------------------------------------------|
| Attach success    | `TAP attach : samtap0 -> R0_re/eth0/0 fd=`           | -                                                         | -                                                     |
| Thread spawn      | `TAP recv thread started`                            | -                                                         | -                                                     |
| Clean detach      | `TAP recv thread exited` AND `TAP detach`            | -                                                         | -                                                     |
| Attach failure    | -                                                    | `TAP ioctl TUNSETIFF failed` AND `errno=1`                | -                                                     |
| Mutual exclusion  | NO `errno=1`                                         | NO `TAP attach : samtap0` AND NO `recv thread started`    | -                                                     |
| Double attach     | second attach: `already attached`                    | (skipped under non-root)                                  | -                                                     |
| Bad iif           | `no such interface ... on node R0_re`                | (skipped under non-root)                                  | -                                                     |
| Regression        | ping + UDP still work                                | ping + UDP still work                                     | -                                                     |

Strong gates:
- The mutual-exclusion under non-root: the failure path must
  not start a thread.
- The clean detach under root: thread MUST exit, not be killed.
  A regression that drops the join would leave a dangling
  thread.

## What's left

ch16: `send_pkt_out` learns to target the TAP fd. The
existing simulator code calls `send_pkt_out(eth_buf, len, oif)`
to put a frame on the UDP-loopback wire. ch16 makes it also
write to `g_tap_fd` when the oif is the TAP-attached interface.

ch17: event-loop + locking. With two recv paths (UDP loopback
+ TAP), the L2 dispatch is being called from two threads.
ch17 reads everything that gets touched concurrently and
either:
- Documents that the current code is safe (with a rationale),
- Adds a per-Node mutex,
- Or restructures into a single-thread event loop.

Then ch18 (TAP IP via CLI), ch19 (ARP two-way), ch20 (GARP),
ch21 (the milestone goal - real ping interop).
