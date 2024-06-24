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

#include <stdbool.h>
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

// ch15: attach a TAP interface to a (node, iif) pair.
//
// Opens the TAP via tap_open, looks up `iif_name` on `node`, then
// spawns a background recv thread that loops on tap_recv_raw and
// calls pkt_receive(node, iif, buf, n) for every frame. The
// thread runs until tap_detach() is called.
//
// `node` is the Node the userspace stack runs as (Phase 6+
// reduces this to "the one Node"; ch15 keeps
// the parameter for symmetry with the simulator).
//
// Returns 0 on success, -1 on error (already attached, bad
// args, tap_open failed, no such interface).
//
// Idempotent on detach-then-reattach; calling attach twice
// without detach is rejected.
struct Node;
struct Interface;
int  tap_attach(struct Node* node, const char* ifname, const char* iif_name);

// ch15: stop the recv thread, close the TAP fd. Safe to call
// from any thread. No-op if not attached.
void tap_detach(void);

// ch15: tap_attach prints "TAP attach : ..."; tap_detach prints
// "TAP detach". The recv thread prints "TAP recv : N bytes on
// <node>/<iif>" for every frame, then dispatches to pkt_receive.

// ch16: send-side integration. comm.c::send_pkt_out asks
// `tap_is_attached_iif` whether the outbound oif corresponds to
// the TAP-attached interface; if yes, `tap_write_frame` is called
// instead of going through the UDP-loopback simulator wire.
//
// Both helpers are no-ops + return safe defaults when no TAP is
// attached, so callers don't need a separate guard.
bool tap_is_attached_iif(struct Interface* iif);
long tap_write_frame(const void* buf, size_t len);

// ch18: bring the kernel-side TAP interface UP. The TUNSETIFF
// ioctl from ch14 creates the interface; ch18 makes it actually
// route packets.
//
// Returns 0 on success, -1 on error. Needs CAP_NET_ADMIN. Caller
// supplies the interface name (must match what was passed to
// tap_attach / tap_open).
int tap_ifup(const char* ifname);

// ch18: assign an IPv4 address + netmask to the kernel-side TAP.
// Replaces the operator's manual `sudo ip addr add 10.0.0.99/24
// dev samtap0` step. `mask_bits` is 0..32; the helper synthesises
// the dotted-quad netmask internally.
//
// Returns 0 on success, -1 on error. Needs CAP_NET_ADMIN.
int tap_set_host_ip(const char* ifname, const char* ip, int mask_bits);

#endif
