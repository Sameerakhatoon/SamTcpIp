# ch18 - static TAP-IP CLI + interface bring-up

Brings the operator's `sudo ip link set up dev samtap0` and
`sudo ip addr add 10.0.0.99/24 dev samtap0` inside the
simulator. Two ioctl wrappers + two CLI verbs.

After ch18, attaching a TAP and configuring its kernel-side
identity is a 3-CLI flow:

```
run tap attach R0_re samtap0 eth0/0
run tap ifup samtap0
run tap host-ip samtap0 10.0.0.99 24
```

The TAP-attached Interface (R0_re's eth0/0) keeps its
simulator-side IP from the topology (20.1.1.1/24). To use the
TAP for real interop in ch19+, the operator picks a host-side
IP on a subnet that overlaps what R0_re thinks it owns (or we
reconfigure R0_re's IP via the existing `config node` CLI -
not in scope for ch18).

## What landed

### tap_ifup(ifname)

```c
struct ifreq req;
strncpy(req.ifr_name, ifname, IFNAMSIZ-1);
ioctl(s, SIOCGIFFLAGS, &req);     // read existing flags
req.ifr_flags |= IFF_UP | IFF_RUNNING;
ioctl(s, SIOCSIFFLAGS, &req);     // write back
```

Read-modify-write so we don't clobber unrelated flags
(`IFF_BROADCAST`, `IFF_MULTICAST`, etc).

### tap_set_host_ip(ifname, ip, mask_bits)

Two ioctls:
- `SIOCSIFADDR` with a `sockaddr_in` holding the IP.
- `SIOCSIFNETMASK` with the same struct, mask synthesised
  from `mask_bits` as a contiguous-high-bits 32-bit value.

Both go through a dummy `socket(AF_INET, SOCK_DGRAM, 0)` -
the ioctl operates on the kernel interface table, the
socket is just a handle.

### CLI

```
run tap ifup <ifname>
run tap host-ip <ifname> <ip> <mask-bits>
```

## End-to-end demo (root)

```
samtcpip> run tap attach R0_re samtap0 eth0/0
TAP attach : samtap0 -> R0_re/eth0/0 fd=4
TAP recv thread started

samtcpip> run tap ifup samtap0
TAP ifup : samtap0 is UP

samtcpip> run tap host-ip samtap0 10.0.0.99 24
TAP host-ip : samtap0 set to 10.0.0.99/24

samtcpip> # other terminal: ip addr show samtap0
12: samtap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 10.0.0.99/24 ...
```

The host kernel now knows samtap0 carries the 10.0.0.0/24
subnet. Pinging 10.0.0.1 from the host triggers an ARP request
out the TAP - which our recv thread sees and feeds into
`pkt_receive`. (R0_re won't answer yet because its eth0/0 is
configured as 20.1.1.1; ch19 wires the ARP responder + we
align IPs.)

## End-to-end demo (non-root)

```
samtcpip> run tap ifup samtap0
TAP ifup : SIOCGIFFLAGS failed : No such device (errno=19)
samtcpip> run tap host-ip samtap0 10.0.0.99 24
TAP host-ip : SIOCSIFADDR failed : Operation not permitted (errno=1)
```

ENODEV on ifup because no TAP was attached (no such interface
exists). EPERM on host-ip would also fire even with an
attached TAP because the ioctl needs `CAP_NET_ADMIN`.

## Design choices

### Why two ioctls for the IP (not one)

Linux's `SIOCSIFADDR` only sets the IP. The mask is a separate
ioctl. We could shortcut by computing the network address via
`SIOCSIFADDR` then walking some other path; the two-call
sequence is the standard idiom.

### Why we synthesise the mask from CIDR bits

The CLI takes `<mask-bits>` (an integer 0..32) rather than a
dotted-quad netmask. Easier to type, easier to validate, and
the simulator's existing `config route` CLI also uses bits.

The synthesised value handles edge cases:
- 0 -> 0x00000000
- 32 -> 0xFFFFFFFF
- N -> `0xFFFFFFFF << (32-N)`

Stored as network-byte-order in the ioctl `sockaddr_in`.

### Why `IFF_RUNNING` alongside `IFF_UP`

Linux distinguishes "administratively UP" (`IFF_UP`) from
"link is RUNNING" (`IFF_RUNNING`). For TAP devices, both are
set together once we flip them - there's no physical link to
deal with. Setting both matches what `ip link set up` does
under the hood.

### Why a fresh AF_INET socket per ioctl

The ioctls don't care which socket they're called on; they
manipulate the kernel's interface table. Using a fresh
DGRAM socket avoids touching the TAP fd or any per-Node socket.

Closing the socket immediately after the ioctl is fine - the
ioctl has already committed kernel-side.

### Why we DON'T set the simulator-side IP from this chapter

`R0_re`'s eth0/0 has an IP set by the topology builder. We
could expose a CLI to change it. ch18 deliberately doesn't,
because:

- The topology IP is a real test fixture that other chapters'
  tests depend on (ARP, ping at 20.1.1.x).
- Changing R0_re's IP would require updating those tests.
- The next chapters (ch19+) will either reconfigure or work
  with whatever IP the topology gave us.

When we collapse to one Node (per PLAN.md rule 4), the
simulator-side IP becomes the only IP; the host-side IP must
match. That refactor is post-MVP.

### Why we don't validate the IP / mask combination

Could check that the IP is not all-zeros, the broadcast
address, etc. Doesn't help operator UX much - if they typo, the
ioctl errors loud enough for them to notice.

## What's NOT here

- Setting the simulator-side IP from this chapter.
- Bringing the interface DOWN (`tap_ifdown`).
- Removing the IP (`SIOCDIFADDR`).
- Setting MTU.
- Setting the broadcast address explicitly.
- Validating the IP is in a sensible subnet.
- Default route via the TAP.

## Test discipline

| Axis                | Positive (root)                                    | Positive (non-root)                              | Negative                                              |
|---------------------|----------------------------------------------------|--------------------------------------------------|-------------------------------------------------------|
| Full sequence       | `TAP attach` + `ifup ... is UP` + `host-ip ... set to`| -                                              | NO `errno=` on any ioctl                              |
| ifup failure        | -                                                  | `TAP ifup : SIOCGIFFLAGS failed`                 | NO `is UP`                                            |
| host-ip failure     | -                                                  | `TAP host-ip :` + `errno=`                       | NO `set to 10.0.0.99`                                 |
| Ping regression     | `Ping reply : R0_re : seq=3 from 20.1.1.2`         | `Ping reply : R0_re : seq=3 from 20.1.1.2`       | -                                                     |

## What's left

Phase 1 has 3 chapters to go to hit the goal:

- **ch19**: ARP two-way over the TAP wire. R0_re answers ARP
  requests for its own IP that arrive via TAP; R0_re initiates
  ARP via TAP when it needs the next-hop MAC.
- **ch20**: gratuitous ARP on IP assignment. When the
  simulator-side IP changes (or first comes up), broadcast a
  GARP so the kernel's ARP cache learns us immediately.
- **ch21**: end-to-end demo - host pings us at our IP, we get
  a reply. We ping the host's IP, the host kernel's ARP +
  ICMP do the rest.

Then Milestone 2: TCP.
