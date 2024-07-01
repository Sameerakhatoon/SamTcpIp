#ifndef SAMTCPIP_UDP_H
#define SAMTCPIP_UDP_H

// RFC 768 UDP. ch13 ships:
//   - 8-byte UdpHdr (src_port, dst_port, length, checksum) packed.
//   - Pseudo-header checksum: src_ip + dst_ip + 0 + protocol +
//     udp_len prepended to the segment for the inet_checksum hash.
//   - Per-Node port -> handler binding table so multiple apps can
//     multiplex on one Node.
//   - L3 dispatch (udp_recv on IP_PROTO_UDP=17) that verifies
//     the checksum, looks up the handler, calls it.
//   - Originate primitive `udp_send_pkt` + a CLI verb.
//   - Built-in `udp_echo_handler` (RFC 862-ish) + a printer sink.
//
// Byte-order: UdpHdr fields are NETWORK byte order on the wire
// (same convention ch11 set for ICMP). The IpHdr a handler sees is
// HOST order (L3 converts it at ingress, ch43); the pseudo-header
// htonl's the addresses back so the checksum matches a real peer.
//
// We ship only what's needed for ch13. UDP
// Port-Unreach ICMP error emit + RFC 768's "transmitted csum = 0
// disables verify" special case come when their chapters need
// them.

#include <stdbool.h>
#include <stddef.h>
#include "../graph.h"
#include "../gluethread/glthread.h"

// Forward declaration breaks the Layer3 -> Layer4 cycle.
struct IpHdr;

#define IP_PROTO_UDP        17

#pragma pack(push, 1)
typedef struct UdpHdr {
    unsigned short src_port;       // NBO
    unsigned short dst_port;       // NBO
    unsigned short length;         // NBO; UdpHdr + payload bytes
    unsigned short checksum;       // ones-complement over pseudo+udp+payload
} UdpHdr;
#pragma pack(pop)

// Per-port receive handler. Runs on the detached packet-receiver
// thread; MUST NOT block.
typedef void (*UdpPortHandler)(Node* node, Interface* iif,
                               struct IpHdr* ip_hdr, UdpHdr* udp_hdr,
                               char* payload, size_t payload_size);

typedef struct UdpBinding UdpBinding;
struct UdpBinding {
    Node*          node;           // bindings are shared across nodes
    unsigned short port;           // host-byte-order
    UdpPortHandler handler;
    GlThread       glue;
};
GLTHREAD_TO_STRUCT(glue_to_udp_binding, UdpBinding, glue);

// Bind handler to (node, port). Re-bind replaces silently.
bool udp_bind(Node* node, unsigned short port, UdpPortHandler handler);
void udp_unbind(Node* node, unsigned short port);

// Register the L3 dispatcher on protocol 17. Call once at startup.
void udp_register(void);

// Originate a UDP datagram. `dst_ip` is host byte order (same as
// ICMP / IP elsewhere).
void udp_send_pkt(Node* node, unsigned int dst_ip,
                  unsigned short src_port, unsigned short dst_port,
                  const char* payload, size_t payload_size);

// Test hook: XOR one bit of the computed checksum before emit.
// Receiver MUST drop. Used by tests/13-udp.sh.
void udp_test_force_csum_corruption(bool on);

// Built-in echo handler (RFC 862-ish). Echoes payload back to
// the original src_ip:src_port verbatim.
void udp_echo_handler(Node* node, Interface* iif,
                      struct IpHdr* ip_hdr, UdpHdr* udp_hdr,
                      char* payload, size_t payload_size);

// Diagnostic sink: prints and drops. Tests use this as the
// originator's src_port so echo replies land where they can be
// asserted on.
void udp_printer_handler(Node* node, Interface* iif,
                         struct IpHdr* ip_hdr, UdpHdr* udp_hdr,
                         char* payload, size_t payload_size);

// Bind {port 7 -> echo, port 12345 -> printer} on every Node in
// the topology. Tests rely on these being pre-bound.
void udp_install_default_handlers(Graph* topo);

#define UDP_PRINTER_PORT    12345
#define UDP_ECHO_PORT       7

#endif
