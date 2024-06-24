#ifndef SAMTCPIP_PMTU_H
#define SAMTCPIP_PMTU_H

// ch39: Path MTU Discovery (RFC 1191).
//
// Per-process cache keyed by destination IP (host byte order). When
// the stack receives an ICMP Type 3 Code 4 ("Fragmentation Needed,
// DF set") for some destination, the next-hop MTU carried in the
// ICMP body lands here. The originate path consults the cache:
//
//   per_frag_payload = min(IP_MAX_FRAG_PAYLOAD,
//                          cached_mtu - sizeof(IpHdr))
//
// Default behaviour (no entry): per_frag_payload =
// IP_MAX_FRAG_PAYLOAD. So the cache is purely a CONSTRAINT - it can
// only make us send SMALLER fragments. That matches RFC 1191's
// "discovery shrinks, never grows".
//
// API is intentionally tiny - one allocator-free static array is
// plenty for the test rig.

void          pmtu_install(unsigned int dst_ip_host, unsigned int mtu);
unsigned int  pmtu_lookup(unsigned int dst_ip_host);  // 0 = no entry
void          pmtu_clear(unsigned int dst_ip_host);   // 0 = clear all
void          pmtu_dump(void);

// ---- RFC 792 / RFC 1191 ICMP error wire constants -----------------
//
// We didn't ship these in ch11 (only what we use).
// Now we use them.
#define ICMP_DEST_UNREACH     3
#define ICMP_FRAG_NEEDED      4

#pragma pack(push, 1)
// RFC 792 Type 3 message body. The original RFC reserved 4 bytes
// after the header; RFC 1191 redefines bytes 6-7 as "Next-Hop MTU".
// Followed on the wire by the original IP header + 8 bytes of orig
// payload, which the receiver uses to figure out WHICH destination
// hit the MTU wall.
typedef struct IcmpDestUnreach {
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;
    unsigned short unused;
    unsigned short next_hop_mtu;
    // followed by: orig IpHdr (20 bytes) + orig 8 bytes of L4 payload
} IcmpDestUnreach;
#pragma pack(pop)

#endif
