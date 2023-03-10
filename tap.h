#ifndef SAMTCPIP_TAP_H
#define SAMTCPIP_TAP_H

// Linux TAP device primitive (ch14, Milestone 1 Phase 1 start).
//
// The first piece of the project that talks to a real kernel
// network interface instead of the simulator's UDP-loopback wire.
//
// Scope of THIS chapter: a minimal open/send/recv/close API plus
// CLI hooks for manual exercise. NOT integrated into the L2/L3
// pipeline yet (the simulator's per-Node UDP wire is unchanged).
// ch15 wires TAP recv into pkt_receive; ch16 wires send_pkt_out
// to write to TAP.
//
// Permission model:
//   - opening /dev/net/tun: needs r/w access. Distro default is
//     0666, so any user can open.
//   - ioctl(TUNSETIFF, IFF_TAP | IFF_NO_PI): needs CAP_NET_ADMIN.
//     As a regular user, fails with EPERM. Test suite asserts
//     that diagnostic and skips the success path; sudo runs see
//     the success path.

#include <stddef.h>

// Linux IFNAMSIZ is 16; mirror it here so callers don't have to
// include kernel headers.
#define TAP_NAME_MAX        16

// Open a TAP interface named `ifname` (e.g. "samtap0") in
// IFF_TAP | IFF_NO_PI mode. Returns the fd, or -1 on error. On
// error, prints a diagnostic including `errno` so the test can
// grep for the failure mode.
//
// `ifname` may be the empty string; the kernel allocates one.
// Pass a real name when you want a predictable interface to
// attach `ip addr` / tcpdump to.
int  tap_open(const char* ifname);

// Close an fd returned by tap_open. Calling with -1 is a no-op.
void tap_close(int fd);

// Write `len` bytes from `buf` to the TAP. Returns bytes written
// (==len for a well-behaved TAP) or -1. The kernel sees these
// as an inbound ethernet frame on the TAP interface.
long tap_send_raw(int fd, const void* buf, size_t len);

// Read up to `max` bytes from the TAP into `buf`. Returns frame
// size or -1. Frames the kernel emits out the TAP (e.g. ARP
// requests after `ip link set up dev samtap0`) appear here.
long tap_recv_raw(int fd, void* buf, size_t max);

#endif
