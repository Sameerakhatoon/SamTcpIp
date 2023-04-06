#ifndef SAMTCPIP_PCAP_H
#define SAMTCPIP_PCAP_H

// libpcap-format frame capture (ch28).
//
// Standard global header + per-record header. LINKTYPE_ETHERNET
// so wireshark/tcpdump can read the output directly.
//
// Single-instance: one capture file open at a time. Calls are
// no-ops when no capture is active, so callers (comm.c::send_pkt_out
// and pkt_receive) don't need a guard.

#include <stdbool.h>
#include <stddef.h>

// Open `path` for capture. Writes the 24-byte global header.
// Returns 0 on success, -1 on error.
int  pcap_open_file(const char* path);

// Close the active capture. No-op if none.
void pcap_close_file(void);

// Append a frame record (16-byte record header + bytes).
// Caller supplies the wire frame (eth dst..payload). No-op if
// no capture is active.
void pcap_dump_frame(const void* buf, size_t len);

#endif
