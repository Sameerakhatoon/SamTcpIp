# ch14 - TAP primitive

First chapter that talks to a real Linux kernel network
interface instead of the simulator's UDP-loopback wire. Phase 0
of Milestone 1 was "real bytes" (ch11/12/13). Phase 1 starts
here. The bytes get a real home.

ch14 is intentionally narrow: just the open/close/send/recv
syscall wrappers + CLI hooks. The recv pipeline is unchanged.
ch15 wires TAP into `pkt_receive`; ch16 wires `send_pkt_out` to
the TAP fd.

## What landed

### tap.{c,h}

Four functions:

```c
int  tap_open(const char* ifname);
void tap_close(int fd);
long tap_send_raw(int fd, const void* buf, size_t len);
long tap_recv_raw(int fd, void* buf, size_t max);
```

The dance in `tap_open`:
1. `open("/dev/net/tun", O_RDWR)` - returns an fd, never the
   actual interface.
2. Fill an `ifreq` with the desired name and flags:
   - `IFF_TAP` - ethernet frames (versus `IFF_TUN`'s L3 packets).
     The userspace stack needs L2, so TAP.
   - `IFF_NO_PI` - suppress the 4-byte "packet info" prefix the
     kernel would prepend. With this flag, what we read is
     exactly the wire frame starting at dst_mac.
3. `ioctl(fd, TUNSETIFF, &ifreq)` - turns the fd into a handle
   to the named TAP interface. This is the privileged step.

### CLI

```
run tap open <ifname>
run tap close
```

Stashes the fd in a single static `g_tap_fd`. ch14 only needs
one TAP at a time; later chapters can grow this.

### Build wiring

`tap.{c,h}` live at the project root (alongside `comm.c`), not
inside a Layer directory. The TAP is BELOW Layer 2 in the model
- it's the wire, not a protocol.

`build/tap.o` added to OBJECTS. `nwcli.c` includes `tap.h`.

## Permission model + test layout

The Linux semantics:
- `open /dev/net/tun` is unprivileged (default mode 0666). Any
  user can get an fd.
- `ioctl(TUNSETIFF, IFF_TAP | IFF_NO_PI)` requires
  `CAP_NET_ADMIN`. As a regular user it fails with `EPERM`
  (errno=1, "Operation not permitted").

The test branches on `id -u`:
- **Non-root**: assert the EPERM diagnostic line appears
  (textual + numeric), AND the success line ("TAP opened")
  does NOT.
- **Root**: assert "TAP opened" appears, AND the EPERM
  diagnostic does NOT.

This lets the test pass under our usual non-root harness AND
under `sudo ./tests/run-all.sh` without any special skipping.

## End-to-end demo (non-root)

```
samtcpip> run tap open samtap0
TAP ioctl TUNSETIFF failed : Operation not permitted (errno=1)
samtcpip> run tap close
TAP closed
```

The diagnostic format pins both the strerror text and the
numeric errno so a future change in glibc's wording doesn't
silently break the test.

## End-to-end demo (root)

```
samtcpip> run tap open samtap0
TAP opened : ifname=samtap0 fd=4
samtcpip> run tap close
TAP closed
```

Other terminal:
```
$ ip link show samtap0
12: samtap0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 ...
```

The interface exists, owned by our process. The simulator
hasn't moved any bytes through it yet - that's ch15/ch16.

## Design choices

### Why IFF_NO_PI

Without it, every read returns a 4-byte prefix
`(flags:u16, proto:u16)` before the actual frame. With it,
`read(fd, buf, max)` returns the frame starting at dst_mac.

ch15 will integrate TAP recv with `pkt_receive`. That function
expects raw ethernet frames. NO_PI lets us pass the buffer
through with no offset arithmetic - simpler + matches the
abstraction.

### Why IFF_TAP not IFF_TUN

TUN gives L3 packets (the kernel strips ethernet). TAP gives
ethernet frames. We want TAP because:
- ARP only exists at L2.
- The userspace stack DOES the L2/L3 split itself.
- TAP closely matches what a real NIC sees.

### Why a single static `g_tap_fd`

The userspace stack is one Node (per PLAN.md rule 4). One TAP
fd suffices. A multi-TAP setup would need a Node-level field
plus per-Node thread; not scope for ch14.

### Why diagnostics print errno BOTH textually and numerically

`strerror(errno)` is human-readable but its wording isn't
guaranteed stable across glibc versions ("Operation not
permitted" vs "Permission denied" - different errnos!). The
numeric form lets the test assert the EXACT failure mode (1 =
EPERM, 13 = EACCES) without ambiguity.

### Why we don't bring the interface up

`ip link set up dev samtap0` requires `CAP_NET_ADMIN` too. We
could `ioctl(SIOCSIFFLAGS)` ourselves, but for ch14's scope
(open + close) the interface stays DOWN. The test docs would
say `sudo ip link set up dev samtap0` if we tried real send/recv.

ch15 will wire a recv thread on the fd; the interface still
needs to be UP for the kernel to forward frames to us. We add
the `set up` ioctl with it.

### Why no send/recv test in ch14

The wrappers exist (`tap_send_raw` / `tap_recv_raw`). Exercising
them needs:
- A real TAP interface (root).
- An IP address (which kernel-side configuration we haven't
  built).
- A real test peer (kernel ARP or ping).

That's a lot of moving parts for ch14. ch15 sets up the recv
thread + a "loopback test" (read what we wrote). ch16 + ch17
make real interop possible.

For ch14: open/close is the contract; tests assert the open
flow works AND fails the right way.

### Why we keep `comm.c`'s UDP-loopback simulator wire

The simulator's UDP-between-Node wire is still how R0/R1/R2
talk in the test topology. ch14 doesn't replace it; it adds an
ADDITIONAL real-wire path. The two coexist:
- Inter-Node traffic: UDP loopback (simulator wire).
- Real Linux interop: TAP fd (real wire).

Eventually the test topology shrinks to one Node and the UDP
wire goes away. Per PLAN.md rule 4 we get there incrementally;
ch14 doesn't force it.

## What's NOT here

- Bringing the interface up (`ioctl(SIOCSIFFLAGS, IFF_UP)`).
- Assigning the IP from inside our code
  (`ioctl(SIOCSIFADDR)`). For now an operator does
  `sudo ip addr add 10.0.0.1/24 dev samtap0`.
- Persistent TAP interfaces (`ioctl(TUNSETPERSIST)`). We
  open/use/close in one process lifetime.
- Multiple TAP fds. Single `g_tap_fd`.
- Send / recv exercise tests. Wrappers exist; ch15 tests them
  end-to-end via the recv pipeline.
- Integration with `pkt_receive` (ch15) or `send_pkt_out`
  (ch16).
- Hex-string send / hex-dump recv CLIs. We can add later if
  debugging needs them.

## Test discipline

| Axis             | Positive (root)                                     | Positive (non-root)                                        | Negative                                              |
|------------------|-----------------------------------------------------|------------------------------------------------------------|-------------------------------------------------------|
| Open success     | `TAP opened : ifname=samtap0 fd=`                   | -                                                          | -                                                     |
| Open failure     | -                                                   | `TAP ioctl TUNSETIFF failed`                               | -                                                     |
| Open failure     | -                                                   | `Operation not permitted` AND `errno=1`                    | -                                                     |
| Mutual exclusion | NO `errno=1`                                         | NO `TAP opened : ifname=`                                  | -                                                     |
| Close            | `TAP closed`                                        | `TAP closed`                                               | -                                                     |
| Regression       | ping + UDP still work                               | ping + UDP still work                                      | -                                                     |

The mutual-exclusion gates are the strong ones: the EPERM line
and the success line must NEVER both appear in the same run.
That catches a regression where someone "fixes" the error path
to print both.

## What's left

ch14 was deliberately narrow. The next chapters in Phase 1
make the TAP USEFUL:

- ch15: TAP recv thread that pipes received frames into
  `pkt_receive`. Test: open TAP, write a known frame from
  outside, observe it land in the L2 dispatch logs.
- ch16: `send_pkt_out` learns to target a TAP fd (in addition
  to its existing UDP-loopback target). Test: ping us from the
  host, observe ARP reply emerge on the host's tcpdump.
- ch17: the event-loop / thread / locking model. With ch15
  adding a recv thread, the locking discipline needs to be
  designed not accreted.
- ch18: static TAP-IP CLI - assign 10.0.0.1/24 to samtap0 from
  inside our code so we don't need `sudo ip addr add` as a
  prerequisite.
- ch19: ARP two-way over TAP (we initiate AND answer).
- ch20: gratuitous ARP on IP assignment.
- ch21: the milestone goal - tcpdump on the host shows our
  stack speaking real ethernet.

Then Milestone 2 (TCP).
