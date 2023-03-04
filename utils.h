#ifndef SAMTCPIP_UTILS_H
#define SAMTCPIP_UTILS_H

// Tiny utilities shared across modules: subnet-mask application
// (used by ARP / routing), the broadcast-MAC helpers (used by
// the ethernet layer), and the RFC 1071 Internet checksum
// (used by ICMP since ch11 and IP since ch12).

#include <stdbool.h>
#include <stddef.h>

// Apply an IPv4 prefix mask to `prefix` and write the result to
// `str_prefix` (16-byte buffer). E.g. apply_mask("122.1.1.1", 24, x)
// fills x with "122.1.1.0".
void apply_mask(char* prefix, char mask, char* str_prefix);

// Stamp the all-ones 48-bit broadcast MAC into a 6-byte buffer.
void layer2_fill_with_broadcast_mac(char* mac_array);

// RFC 1071 Internet Checksum.
//
// 16-bit ones-complement sum over `len` bytes at `data`, returned
// complemented. Byte-stable: reads bytes as big-endian words so
// the result depends only on byte values, not host architecture.
//
// Emit: zero the checksum field in the buffer, call inet_checksum,
// htons the returned value, store it.
//
// Verify: htons-stored values mean the receiver runs the algorithm
// over the WHOLE buffer (including the stored checksum) and gets 0.
//
// Used by ICMP (ch11) and IP (ch12). ch11 originally inlined this
// in Layer3/icmp.c; ch12 promotes it here so IP can share it.
unsigned short inet_checksum(const void* data, size_t len);

#define IS_MAC_BROADCAST_ADDR(mac)                                     \
    ((unsigned char)(mac)[0] == 0xFF && (unsigned char)(mac)[1] == 0xFF && \
     (unsigned char)(mac)[2] == 0xFF && (unsigned char)(mac)[3] == 0xFF && \
     (unsigned char)(mac)[4] == 0xFF && (unsigned char)(mac)[5] == 0xFF)

#endif
