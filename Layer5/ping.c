#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../graph.h"
#include "../net.h"
#include "../Layer3/layer3.h"
#include "../Layer3/icmp.h"
#include "../Layer3/pmtu.h"
#include "../Layer3/layer3.h"
#include "ping.h"

// Forward declarations.
static void ping_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                      char* payload, size_t payload_size);
static void ip_int_to_str(unsigned int ip_host_order, char* out16);
static void send_one_request(Node* node, char* dst_ip_str, short seq, bool corrupt,
                             unsigned char ttl);
void        ping_register(void);
void        ping_send_request(Node* node, char* dst_ip_str, short seq);
void        ping_send_request_bad_checksum(Node* node, char* dst_ip_str, short seq);

// 16-byte ASCII payload after the IcmpHdr. Real ping fills with
// timestamps; ours uses a stable string so the bytes-on-wire are
// deterministic. Receiver echoes verbatim per RFC 792.
#define PING_FILLER_BYTES   16
#define PING_FILLER         "samtcpip-ping---"     // exactly 16 bytes

static void ip_int_to_str(unsigned int ip_host_order, char* out16){
    unsigned int net = htonl(ip_host_order);
    inet_ntop(AF_INET, &net, out16, 16);
    out16[15] = '\0';
}

static void ping_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                      char* payload, size_t payload_size){
    (void)iif;
    if(payload_size < sizeof(IcmpHdr)){
        printf("Ping recv : %s : runt ICMP, %zu bytes\n",
               node->node_name, payload_size);
        return;
    }
    // RFC 1071: verify by running checksum over the whole message
    // including the stored checksum field. Valid -> 0.
    if(icmp_checksum(payload, payload_size) != 0){
        printf("Ping recv : %s : ICMP checksum invalid (drop)\n",
               node->node_name);
        return;
    }

    IcmpHdr* in = (IcmpHdr*)payload;

    char src_str[16];
    ip_int_to_str(ip_hdr->src_ip, src_str);

    unsigned short seq_host = ntohs(in->sequence);

    if(in->type == ICMP_ECHO_REQUEST){
        // RFC 792: an Echo Reply MUST echo back the request's data.
        // Copy verbatim, flip type, recompute checksum.
        unsigned char reply_buf[64];
        if(payload_size > sizeof(reply_buf)){
            printf("Ping recv : %s : oversized ICMP, drop\n", node->node_name);
            return;
        }
        memcpy(reply_buf, payload, payload_size);

        IcmpHdr* reply = (IcmpHdr*)reply_buf;
        reply->type     = ICMP_ECHO_REPLY;
        reply->code     = 0;
        reply->checksum = 0;
        // Stored in NBO so the wire bytes are deterministic and the
        // receiver's algorithm (reads big-endian words) yields 0.
        reply->checksum = htons(icmp_checksum(reply_buf, payload_size));

        printf("Ping recv : %s : ICMP echo request seq=%u from %s, replying\n",
               node->node_name, seq_host, src_str);
        demote_packet_to_layer3(node, (char*)reply_buf, payload_size,
                                ICMP_PROTO, ip_hdr->src_ip);
        return;
    }
    if(in->type == ICMP_ECHO_REPLY){
        printf("Ping reply : %s : seq=%u from %s ttl=%u\n",
               node->node_name, seq_host, src_str, ip_hdr->ttl);
        return;
    }
    // A router dropped one of our echo requests on its TTL. The
    // body quotes the request's IP header (wire order) and its first
    // 8 bytes: the echo header with the sequence number.
    if(in->type == ICMP_TIME_EXCEEDED){
        const unsigned char* q = (const unsigned char*)payload + ICMP_ERROR_HDR_SIZE;
        size_t qlen = payload_size - ICMP_ERROR_HDR_SIZE;
        IpHdr* orig = (IpHdr*)q;
        size_t ohl = payload_size >= ICMP_ERROR_HDR_SIZE + sizeof(IpHdr) ? IP_HDR_IHL(orig) * 4u : 0;
        if(ohl < sizeof(IpHdr) || qlen < ohl + sizeof(IcmpHdr) || orig->protocol != ICMP_PROTO){
            printf("Ping recv : %s : Time Exceeded from %s, not about a ping\n",
                   node->node_name, src_str);
            return;
        }
        IcmpHdr* req = (IcmpHdr*)(q + ohl);
        if(req->type != ICMP_ECHO_REQUEST){
            return;
        }
        unsigned short seq = ntohs(req->sequence);
        printf("Ping recv : %s : Time Exceeded seq=%u from %s\n", node->node_name, seq, src_str);
        return;
    }
    // ch39: RFC 1191 PMTUD. ICMP Type 3 Code 4 = "Fragmentation
    // Needed, DF set". Body carries next-hop MTU and the orig IP
    // header (so we know WHICH dst was unreachable). Install the
    // discovered MTU in the per-dst PMTU cache; the next originate
    // to that dst will fragment to fit.
    if(in->type == ICMP_DEST_UNREACH && in->code == ICMP_FRAG_NEEDED){
        if(payload_size < sizeof(IcmpDestUnreach) + sizeof(IpHdr)){
            printf("Ping recv : %s : runt Frag-Needed (%zu bytes)\n",
                   node->node_name, payload_size);
            return;
        }
        IcmpDestUnreach* du = (IcmpDestUnreach*)payload;
        unsigned short next_mtu = ntohs(du->next_hop_mtu);
        // The quoted original header is raw wire bytes (L3 only
        // converts the outer header), so its dst is network order.
        IpHdr* orig = (IpHdr*)(payload + sizeof(IcmpDestUnreach));
        unsigned int orig_dst = ntohl(orig->dst_ip);
        char dst_str[16];
        ip_int_to_str(orig_dst, dst_str);
        printf("Ping recv : %s : Frag-Needed for %s (next-hop MTU %u)\n",
               node->node_name, dst_str, next_mtu);
        if(next_mtu >= sizeof(IpHdr) + 8){    // sanity
            pmtu_install(orig_dst, next_mtu);
        }
        return;
    }
    printf("Ping recv : %s : unhandled ICMP type=%u code=%u\n",
           node->node_name, in->type, in->code);
}

void ping_register(void){
    l3_register_l4_handler(ICMP_PROTO, ping_recv);
}

// Build + emit one ECHO REQUEST. When `corrupt` is true, XOR one
// bit of the checksum after computing it (test hook for the
// receiver's verify path).
static void send_one_request(Node* node, char* dst_ip_str, short seq, bool corrupt,
                             unsigned char ttl){
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, dst_ip_str, &dst_net) != 1){
        printf("Ping : %s : bad ip `%s`\n", node->node_name, dst_ip_str);
        return;
    }
    unsigned int dst_host = htonl(dst_net);

    unsigned char buf[sizeof(IcmpHdr) + PING_FILLER_BYTES];
    memset(buf, 0, sizeof(buf));

    IcmpHdr* hdr = (IcmpHdr*)buf;
    hdr->type       = ICMP_ECHO_REQUEST;
    hdr->code       = 0;
    hdr->checksum   = 0;
    // identifier: low 16 bits of the Node pointer disambiguates
    // concurrent pings from different nodes against the same dst.
    hdr->identifier = htons((unsigned short)((unsigned long)node & 0xFFFF));
    hdr->sequence   = htons((unsigned short)seq);
    memcpy(buf + sizeof(IcmpHdr), PING_FILLER, PING_FILLER_BYTES);

    hdr->checksum = htons(icmp_checksum(buf, sizeof(buf)));
    if(corrupt){
        hdr->checksum ^= htons(1);
    }

    demote_packet_to_layer3_ttl(node, (char*)buf, sizeof(buf),
                                ICMP_PROTO, dst_host, ttl);
}

void ping_send_request(Node* node, char* dst_ip_str, short seq){
    send_one_request(node, dst_ip_str, seq, false, 0);
}

void ping_send_request_ttl(Node* node, char* dst_ip_str, short seq, unsigned char ttl){
    send_one_request(node, dst_ip_str, seq, false, ttl);
}

void ping_send_request_bad_checksum(Node* node, char* dst_ip_str, short seq){
    send_one_request(node, dst_ip_str, seq, true, 0);
}
