#ifndef SAMTCPIP_UTILS_H
#define SAMTCPIP_UTILS_H

// Tiny utilities shared across modules: subnet-mask application
// (used by ARP / routing) and the broadcast-MAC helpers (used by
// the ethernet layer).

#include <stdbool.h>

// Apply an IPv4 prefix mask to `prefix` and write the result to
// `str_prefix` (16-byte buffer). E.g. apply_mask("122.1.1.1", 24, x)
// fills x with "122.1.1.0".
void apply_mask(char* prefix, char mask, char* str_prefix);

// Stamp the all-ones 48-bit broadcast MAC into a 6-byte buffer.
void layer2_fill_with_broadcast_mac(char* mac_array);

#define IS_MAC_BROADCAST_ADDR(mac)                                     \
    ((unsigned char)(mac)[0] == 0xFF && (unsigned char)(mac)[1] == 0xFF && \
     (unsigned char)(mac)[2] == 0xFF && (unsigned char)(mac)[3] == 0xFF && \
     (unsigned char)(mac)[4] == 0xFF && (unsigned char)(mac)[5] == 0xFF)

#endif
