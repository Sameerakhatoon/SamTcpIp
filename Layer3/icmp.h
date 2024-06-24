#ifndef SAMTCPIP_ICMP_H
#define SAMTCPIP_ICMP_H

// RFC 792 ICMP wire format + RFC 1071 Internet checksum.
//
// ch11 ships the bare minimum needed to replace ping's homegrown
// PING_PROTO=201 + PingMsg with a real ICMP echo:
//   - IcmpHdr packed struct: type, code, checksum, identifier, sequence
//   - icmp_checksum(): 16-bit ones-complement sum, RFC 1071
//   - constants: ICMP_PROTO=1 (IANA), ECHO_REQUEST=8, ECHO_REPLY=0
//
// We ship ONLY what we use. Error message
// constants (Dest Unreach, Time Exceeded, Frag Needed, Redirect)
// come when we ship those errors, not pre-emptively.
//
// Byte-order note:
//   ICMP fields (identifier, sequence, checksum) are NETWORK byte
//   order on the real wire. The course's IP src_ip / dst_ip have
//   lived in HOST byte order since ch5. ch11 honours real ICMP
//   byte order for the ICMP fields and leaves IP alone. We close
//   the IP host-order debt when we wire TAP (Milestone 1 ch18) on
//   any path that touches the real wire.
//
// Checksum self-consistency property: receiver runs the same
// algorithm over the full received message (including the on-wire
// checksum field). If the message was not corrupted, the result is
// 0. icmp_checksum() returns the complemented sum, so a valid msg
// yields 0.

#include <stddef.h>

#define ICMP_PROTO            1
#define ICMP_ECHO_REPLY       0
#define ICMP_ECHO_REQUEST     8

#pragma pack(push, 1)
typedef struct IcmpHdr {
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;       // ones-complement, stored as-computed
    unsigned short identifier;     // NBO
    unsigned short sequence;       // NBO
} IcmpHdr;
#pragma pack(pop)

// RFC 1071: 16-bit ones-complement sum over `len` bytes at `data`,
// returned complemented. The caller is responsible for zeroing the
// checksum field in the buffer before calling for emit, and for
// running this over the whole received buffer (including the
// stored checksum) for verify.
unsigned short icmp_checksum(const void* data, size_t len);

#endif
