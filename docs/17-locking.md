# ch17 - event-loop + threading + locking model

The "thinking chapter" PLAN.md scheduled here. ch15 added a
TAP recv thread; ch16 made egress route through TAP. Both
chapters' tests pass, but we now have **two threads calling
the same `pkt_receive` entry point on possibly the same Node
at the same time**. The course built the simulator under a
"one recv thread, no concurrency" assumption. Time to fix it
before it bites us in ch18+.

ch17 does:
1. Audit what `pkt_receive` and its downstream actually touch.
2. Choose the simplest correct lock model.
3. Ship the lock.
4. Document the rule for future chapters.

## The audit

`pkt_receive(node, iif, pkt, pkt_size)` is the single ingress
choke point. It calls `layer2_frame_recv(node, iif, ...)`
which descends:

- L2 ARP table lookup + insert.
- L2 MAC table lookup + insert.
- L2 dispatch to L3 (`layer3_pkt_recv_from_layer2`).
  - L3 IP-csum verify (`inet_checksum` - pure, no shared state).
  - L3 LPM lookup on the per-Node `RtTable`.
  - L3 local-delivery check (`is_layer3_local_delivery` walks
    the per-Node interfaces - read-only).
  - L3 push-down to L2 send (`layer3_pkt_push_down_to_layer2_for_l2routing`).
    - This synchronously calls `send_pkt_out`.

Shared state touched on the recv path:
| Object               | Read | Write | Per-Node | Lock today |
|----------------------|------|-------|----------|------------|
| ArpTable             | yes  | yes   | yes      | NONE       |
| MacTable             | yes  | yes   | yes      | NONE       |
| RtTable              | yes  | no    | yes      | NONE       |
| Interface.ip / mac   | yes  | no    | yes      | NONE       |
| Node.lo_addr         | yes  | no    | yes      | NONE       |

`send_pkt_out` is reentered from the recv path (L2 forwards a
frame back out). It also touches:
| Object               | Read | Write | Lock today |
|----------------------|------|-------|------------|
| Per-call socket fd   | yes  | yes   | local      |
| `g_tap_fd` (ch15)    | yes  | no    | NONE       |
| `g_tap_iif` (ch15)   | yes  | no    | NONE       |

The races we have to prevent:
1. Two recv threads inserting into the SAME ArpTable / MacTable
   concurrently. Linked-list corruption.
2. One recv thread updating an ArpEntry while another reads it
   on the lookup path. Torn `MacAddr`.
3. The recv path running while `tap_detach` flips
   `g_tap_iif = NULL`. Stale-pointer hand-off into pkt_receive.

We do NOT have to worry about:
- RT / Interface IP changes mid-run. They're set at boot via
  `nwcli_install` and never mutated by recv.
- `send_pkt_out`'s per-call socket - it's stack-local.

## The fix

A single recursive global mutex around `pkt_receive` entry:

```c
static pthread_mutex_t g_pkt_recv_mtx;
static pthread_once_t  g_pkt_recv_mtx_once = PTHREAD_ONCE_INIT;
static void init_pkt_recv_mtx(void){
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_pkt_recv_mtx, &attr);
    pthread_mutexattr_destroy(&attr);
}

int pkt_receive(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    pthread_once(&g_pkt_recv_mtx_once, init_pkt_recv_mtx);
    pthread_mutex_lock(&g_pkt_recv_mtx);
    layer2_frame_recv(node, iif, pkt, pkt_size);
    pthread_mutex_unlock(&g_pkt_recv_mtx);
    return 0;
}
```

That's it.

## Design choices

### Why one global lock, not per-Node

The simplest thing that prevents the races we listed. Per-Node
would let two threads work on different Nodes concurrently,
but:

- We're walking toward "one Node" per PLAN.md rule 4.
  Per-Node locks complicate that collapse.
- Throughput target is "manual ping" + "operator-driven curl",
  not millions of pps. The global lock is invisible at our load.
- A per-Node lock would also need a lock for the inter-Node
  send_pkt_out path because L2-on-Node-A may emit toward
  Node-B's recv socket. The simpler "everyone serializes
  through pkt_receive" model avoids that.

If profiling ever shows the global lock as a bottleneck we
refactor. PLAN.md rule 1 says "if I skipped this would curl
fail?" - per-Node parallelism would not.

### Why recursive

`layer2_frame_recv` calls `layer3_pkt_recv_from_layer2` which
calls `layer3_pkt_push_down_to_layer2_for_l2routing` which
calls `send_pkt_out`. `send_pkt_out` may eventually need to
hold the same lock (when the TAP egress branches into
`pkt_receive`-touching state, or when a future chapter wires
counters that recv also touches).

Recursive lets us NOT design a lock-order discipline today.
The price is a few extra cycles per lock op; we eat it.

When ch18+ pile state on, we can revisit and split into a
read-write or per-table lock if we see a real problem. For
ch17 the design rule is "anything reachable from `pkt_receive`
is mutex-protected; emit paths that don't touch shared state
are free."

### Why `pthread_once` initialization

The mutex would need a `pthread_mutex_init` somewhere at
startup. There's no obvious place (testapp.c boots the
topology then drops to REPL; we'd add a one-line call). But
PLAN.md prefers fewer cross-file touches when there's an
in-place alternative.

`pthread_once` runs the init the first time `pkt_receive` is
called from ANY thread, then never again. Cost: one branch
per call. Worth it for the locality.

### Why we don't lock send_pkt_out separately

ch16's send_pkt_out has the TAP branch that calls
`tap_write_frame`. The TAP write touches `g_tap_fd` which is
only mutated by `tap_attach` / `tap_detach` (both CLI-thread
calls). The recv thread reads `g_tap_iif` (also only mutated
by attach/detach).

The interlock today is: the CLI runs the attach/detach calls
synchronously; the recv thread reads atomically (the pointer
is a single word). A torn read is impossible on x86-64 for
aligned pointers; on platforms where it's possible, we'd need
an atomic load. For our scope, the implicit serialization is
adequate.

The `g_pkt_recv_mtx` does NOT cover this. If a future chapter
wires async TAP attach/detach (from a timer thread, say),
we add an explicit `tap_attach_mtx`.

### Why we don't add per-table locks (ArpTable etc)

That would be the "right" textbook answer. The cost: more
code to maintain, harder to evolve, more places to acquire +
release. The benefit: fine-grained parallelism we don't need.

If we later split into per-Node or move to an actor model
(one thread per Node), the per-table locks come for free at
that boundary.

### Why we don't add an event-loop thread model

PLAN.md proposed "event-loop + threading model" as the chapter
title. We considered:
- Single-threaded event loop (one thread, select across all
  fds, dispatch synchronously). Avoids the lock but requires
  rewriting the per-Node UDP fan-in.
- Two threads + global lock (what we shipped).
- Per-Node thread per recv path (heavier).

Option 2 is the smallest diff that makes the program correct.
Option 1 is a future refactor when we have a reason. The plan
in PLAN.md ch17 covered "event-loop OR threading model"; we
picked the latter.

## End-to-end demo

No visible behavior change. The lock is invisible at the log
level. The test stress-runs back-to-back pings and (under root)
TAP-attached pings; the assertions check that the recv path
still works end-to-end - which it does because the lock just
serializes what was already correct under a single thread.

```
samtcpip> run node R0_re ping 20.1.1.2
Ping reply : R0_re : seq=3 from 20.1.1.2

samtcpip> run node R0_re udp 20.1.1.2
UDP printer : R0_re : port 12345 from 20.1.1.2:7 : `hello-from-samtcpip`

samtcpip> run node R0_re ping 20.1.1.2
Ping reply : R0_re : seq=3 from 20.1.1.2
```

Same as without the lock. If the lock deadlocks, the second
run never completes; if it releases prematurely under load,
the receiver might see torn ARP entries and log
`Pkt recvd on unknown interface` - which the test asserts
MUST NOT happen.

## Future scope

The lock is a starting point. PLAN.md Phase 4 (TCP) will add
timers, retransmit threads, and other concurrent state.
Specifically:
- TCP TCB read/write from both the recv thread (incoming
  ACKs) and the retransmit timer (RTO).
- TCP send-queue access from app + recv + timer.

Those need their own discipline. The plan: each new thread
gets a documented role + a documented set of mutexes it
takes, in lock order. ch17's global mutex stays; new threads
add new mutexes; we never tangle them.

## What's NOT here

- Per-Node locks. Global only.
- Per-table locks (ArpTable / MacTable / etc).
- An event-loop refactor.
- A thread-name tagging scheme. `pthread_setname_np` would
  make `htop` more useful when debugging. Cheap; do later.
- A lockdep-style ordering checker.
- Locking around CLI mutations (route add, interface IP
  change). Those happen from the REPL thread which doesn't
  contend with recv; if a future async config path appears,
  we extend.
- Atomic loads on `g_tap_iif` / `g_tap_fd`. Single-word
  aligned reads on x86-64 are atomic by hardware; if we
  ever care about portability beyond Linux/x86-64, we add
  explicit `_Atomic`.

## Test discipline

| Axis             | Positive                                                | Negative                                              |
|------------------|---------------------------------------------------------|-------------------------------------------------------|
| Stress ping      | >=6 replies across 3 ping runs                          | NO `Pkt recvd on unknown interface` (torn aux header) |
| Stress UDP       | >=1 printer log                                         | (presence)                                            |
| Root TAP+load    | `TAP detach` reached cleanly                            | (presence)                                            |
| Suite regression | all of 01..16 pass                                      | -                                                     |

The strong gate is the "interface-name corruption" assertion.
That string only appears when the aux-header strip on the
recv path read a buffer that was being concurrently written.
With the lock, it never appears. Without the lock, under
heavy concurrent load, we'd start seeing it.

## What's left

ch18: static TAP-IP CLI + interface bring-up. We need an IP
on the TAP-attached interface (R0_re's eth0/0) AND the kernel
side needs the interface UP and ideally a matching IP on the
host so frames actually flow. ch18 owns the configuration
plumbing.

Then ch19 (ARP two-way over real TAP wire), ch20 (GARP), and
ch21 - the milestone goal where a host ping reaches us and our
ping reaches the host, both verified with tcpdump.
