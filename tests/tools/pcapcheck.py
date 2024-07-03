#!/usr/bin/env python3
"""Independent RFC wire-format checker for a samtcpip .pcap.

Decodes every frame with network-byte-order rules that owe nothing
to the stack's own structs, and validates:
  - Ethernet II EtherType (0x0806 ARP, 0x0800 IPv4, 0x8100 tag)
  - ARP: htype 1, ptype 0x0800, hlen 6, plen 4, op 1|2, 42-byte frame
  - IPv4: version nibble 4, header checksum, total_length
  - ICMP / UDP / TCP checksums (pseudo-header in network order)
Frames the host kernel sends that we don't speak (IPv6) are counted
as foreign, not errors. Exit 1 if any frame fails.
"""
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def check_frame(f):
    errs = []
    etype, = struct.unpack('!H', f[12:14])
    p = f[14:]
    if etype == 0x8100:
        etype, = struct.unpack('!H', f[16:18])
        p = f[18:]
    if etype == 0x86DD:
        return 'foreign IPv6', errs
    if etype == 0x0806:
        ht, pt, hl, pl, op = struct.unpack('!HHBBH', p[:8])
        if (ht, pt, hl, pl) != (1, 0x0800, 6, 4):
            errs.append('arp fields %r' % ((ht, pt, hl, pl),))
        if op not in (1, 2):
            errs.append('arp op %d' % op)
        if len(f) < 42:
            errs.append('arp frame len %d' % len(f))
        return 'ARP op=%d' % op, errs
    if etype != 0x0800:
        errs.append('ethertype 0x%04x' % etype)
        return 'ethertype 0x%04x' % etype, errs
    if p[0] >> 4 != 4:
        errs.append('ip version byte 0x%02x' % p[0])
        return 'IPv4 (bad)', errs
    ihl = (p[0] & 15) * 4
    tot, _, fo, _, proto = struct.unpack('!HHHBB', p[2:10])
    if csum(p[:ihl]) != 0:
        errs.append('ip checksum')
    if tot > len(p):
        errs.append('ip total_length %d > %d' % (tot, len(p)))
    seg = p[ihl:tot]
    kind = 'IPv4 proto=%d' % proto
    if fo & 0x3FFF:                    # MF set or offset != 0 (DF is 0x4000)
        return kind + ' (fragment)', errs
    if proto == 1 and csum(seg) != 0:
        errs.append('icmp checksum')
    if proto in (6, 17):
        ph = p[12:20] + struct.pack('!BBH', 0, proto, len(seg))
        udp_no_csum = proto == 17 and seg[6:8] == b'\0\0'
        if not udp_no_csum and csum(ph + seg) != 0:
            errs.append('%s checksum' % ('tcp' if proto == 6 else 'udp'))
    return kind, errs


def main(path):
    data = open(path, 'rb').read()
    magic, = struct.unpack('<I', data[:4])
    if magic != 0xa1b2c3d4:
        print('bad pcap magic 0x%08x' % magic)
        return 1
    off, n, bad, kinds = 24, 0, 0, {}
    while off + 16 <= len(data):
        incl, = struct.unpack('<I', data[off + 8:off + 12])
        off += 16
        frame = data[off:off + incl]
        off += incl
        n += 1
        kind, errs = check_frame(frame)
        kinds[kind] = kinds.get(kind, 0) + 1
        if errs:
            bad += 1
            print('frame %d (%d B): %s' % (n, len(frame), '; '.join(errs)))
    print('pcapcheck : frames=%d bad=%d' % (n, bad))
    for k, v in sorted(kinds.items()):
        print('  %-28s %d' % (k, v))
    return 1 if bad else 0


sys.exit(main(sys.argv[1]))
