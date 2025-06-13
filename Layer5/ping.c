#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../graph.h"
#include "../net.h"
#include "../Layer3/layer3.h"
#include "../Layer3/icmp.h"
#include "../Layer3/pmtu.h"
#include "../Layer3/layer3.h"
#include "ping.h"

// In SamOS net/net.c has the syscall waiting for this reply; it waits
// also for a Time Exceeded about one of our requests, and for a
// Destination Unreachable; one call, net_ping_answer (ping.h), with a
// PingAnswer that says what answered. SamTcpIp: net_ping_answer is at
// the end of this file and prints the answer.

// Forward declarations.
static void ping_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                      char* payload, size_t payload_size);
static void ip_int_to_str(unsigned int ip_host_order, char* out16);
static void send_one_request(Node* node, char* dst_ip_str, short seq, bool corrupt,
                             unsigned char ttl, size_t data_bytes, bool df);
void        ping_register(void);
void        ping_send_request(Node* node, char* dst_ip_str, short seq);
void        ping_send_request_bad_checksum(Node* node, char* dst_ip_str, short seq);

// 16-byte ASCII payload after the IcmpHdr. Real ping fills with
// timestamps; ours uses a stable string so the bytes-on-wire are
// deterministic. Receiver echoes verbatim per RFC 792. A request
// with more data repeats the string; the reply's data is checked
// against it (PingAnswer.data_ok).
#define PING_FILLER_BYTES   16
#define PING_FILLER         "samtcpip-ping---"     // exactly 16 bytes

static void ip_int_to_str(unsigned int ip_host_order, char* out16){
    unsigned int net = htonl(ip_host_order);
    inet_ntop(AF_INET, &net, out16, 16);
    out16[15] = '\0';
}

// An ICMP error about one of our echo requests. The body
// quotes the request's IP header (wire order) and its first 8 bytes:
// the echo header with the sequence number. False when it is not
// about an echo request.
static bool ping_quoted_request(char* payload, size_t payload_size,
                                unsigned int* dst, unsigned short* seq){
    if(payload_size < ICMP_ERROR_HDR_SIZE + sizeof(IpHdr)){
        return false;
    }
    const unsigned char* q = (const unsigned char*)payload + ICMP_ERROR_HDR_SIZE;
    size_t qlen = payload_size - ICMP_ERROR_HDR_SIZE;
    IpHdr* orig = (IpHdr*)q;
    size_t ohl = IP_HDR_IHL(orig) * 4u;
    if(ohl < sizeof(IpHdr) || qlen < ohl + sizeof(IcmpHdr) || orig->protocol != ICMP_PROTO){
        return false;
    }
    IcmpHdr* req = (IcmpHdr*)(q + ohl);
    if(req->type != ICMP_ECHO_REQUEST){
        return false;
    }
    *dst = ntohl(orig->dst_ip);
    *seq = ntohs(req->sequence);
    return true;
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
    PingAnswer ans;
    memset(&ans, 0, sizeof(ans));
    ans.from = ip_hdr->src_ip;
    ans.ttl  = ip_hdr->ttl;
    ans.type = in->type;
    ans.code = in->code;

    if(in->type == ICMP_ECHO_REQUEST){
        // RFC 792: an Echo Reply MUST echo back the request's data.
        // Copy verbatim, flip type, recompute checksum. Any size
        // reassembly delivers (the reference had a 64-byte buffer).
        unsigned char* reply_buf = (unsigned char*)malloc(payload_size);
        if(!reply_buf){
            printf("Ping recv : %s : no memory for a %zu-byte reply\n", node->node_name, payload_size);
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
        free(reply_buf);
        return;
    }
    if(in->type == ICMP_ECHO_REPLY){
        const char* data = payload + sizeof(IcmpHdr);
        ans.dst     = ip_hdr->src_ip;
        ans.seq     = seq_host;
        ans.bytes   = (unsigned int)(payload_size - sizeof(IcmpHdr));
        ans.data_ok = true;
        for(size_t i = 0; i < ans.bytes && ans.data_ok; i++){
            ans.data_ok = data[i] == PING_FILLER[i % PING_FILLER_BYTES];
        }
        net_ping_answer(&ans);
        printf("Ping reply : %s : seq=%u from %s ttl=%u\n",
               node->node_name, seq_host, src_str, ip_hdr->ttl);
        return;
    }
    // A router dropped one of our echo requests on its TTL.
    if(in->type == ICMP_TIME_EXCEEDED){
        if(!ping_quoted_request(payload, payload_size, &ans.dst, &ans.seq)){
            printf("Ping recv : %s : Time Exceeded from %s, not about a ping\n",
                   node->node_name, src_str);
            return;
        }
        printf("Ping recv : %s : Time Exceeded seq=%u from %s\n", node->node_name, ans.seq, src_str);
        net_ping_answer(&ans);
        return;
    }
    // Destination Unreachable, any code: about one of our echo
    // requests, the waiting ping hears of it (with the next-hop MTU of
    // a Fragmentation Needed).
    //
    // ch39: RFC 1191 PMTUD. ICMP Type 3 Code 4 = "Fragmentation
    // Needed, DF set". Body carries next-hop MTU and the orig IP
    // header (so we know WHICH dst was unreachable). Install the
    // discovered MTU in the per-dst PMTU cache; the next originate
    // to that dst will fragment to fit.
    if(in->type == ICMP_DEST_UNREACH){
        if(payload_size < sizeof(IcmpDestUnreach) + sizeof(IpHdr)){
            printf("Ping recv : %s : runt Destination Unreachable (%zu bytes)\n",
                   node->node_name, payload_size);
            return;
        }
        IcmpDestUnreach* du = (IcmpDestUnreach*)payload;
        // The quoted original header is raw wire bytes (L3 only
        // converts the outer header), so its dst is network order.
        IpHdr* orig = (IpHdr*)(payload + sizeof(IcmpDestUnreach));
        unsigned int orig_dst = ntohl(orig->dst_ip);
        char dst_str[16];
        ip_int_to_str(orig_dst, dst_str);
        if(in->code == ICMP_FRAG_NEEDED){
            unsigned short next_mtu = ntohs(du->next_hop_mtu);
            ans.mtu = next_mtu;
            printf("Ping recv : %s : Frag-Needed for %s (next-hop MTU %u)\n",
                   node->node_name, dst_str, next_mtu);
            if(next_mtu >= sizeof(IpHdr) + 8){    // sanity
                pmtu_install(orig_dst, next_mtu);
            }
        } else {
            printf("Ping recv : %s : Destination Unreachable code %u for %s from %s\n",
                   node->node_name, in->code, dst_str, src_str);
        }
        if(ping_quoted_request(payload, payload_size, &ans.dst, &ans.seq)){
            net_ping_answer(&ans);
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
                             unsigned char ttl, size_t data_bytes, bool df){
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, dst_ip_str, &dst_net) != 1){
        printf("Ping : %s : bad ip `%s`\n", node->node_name, dst_ip_str);
        return;
    }
    unsigned int dst_host = htonl(dst_net);
    if(!data_bytes){
        data_bytes = PING_FILLER_BYTES;
    }
    size_t size = sizeof(IcmpHdr) + data_bytes;
    unsigned char* buf = (unsigned char*)malloc(size);
    if(!buf){
        return;
    }
    memset(buf, 0, sizeof(IcmpHdr));

    IcmpHdr* hdr = (IcmpHdr*)buf;
    hdr->type       = ICMP_ECHO_REQUEST;
    hdr->code       = 0;
    hdr->checksum   = 0;
    // identifier: low 16 bits of the Node pointer disambiguates
    // concurrent pings from different nodes against the same dst.
    hdr->identifier = htons((unsigned short)((unsigned long)node & 0xFFFF));
    hdr->sequence   = htons((unsigned short)seq);
    for(size_t i = 0; i < data_bytes; i++){
        buf[sizeof(IcmpHdr) + i] = (unsigned char)PING_FILLER[i % PING_FILLER_BYTES];
    }

    hdr->checksum = htons(icmp_checksum(buf, size));
    if(corrupt){
        hdr->checksum ^= htons(1);
    }

    demote_packet_to_layer3_df(node, (char*)buf, size, ICMP_PROTO, dst_host, ttl, df);
    free(buf);
}

void ping_send_request(Node* node, char* dst_ip_str, short seq){
    send_one_request(node, dst_ip_str, seq, false, 0, 0, false);
}

void ping_send_request_ttl(Node* node, char* dst_ip_str, short seq, unsigned char ttl){
    send_one_request(node, dst_ip_str, seq, false, ttl, 0, false);
}

void ping_send_request_ex(Node* node, char* dst_ip_str, short seq, unsigned char ttl,
                          size_t data_bytes, bool df){
    send_one_request(node, dst_ip_str, seq, false, ttl, data_bytes, df);
}

void ping_send_request_bad_checksum(Node* node, char* dst_ip_str, short seq){
    send_one_request(node, dst_ip_str, seq, true, 0, 0, false);
}

// SamTcpIp: in SamOS net_ping_answer wakes the ping syscall waiting for
// this answer. The simulator's ping does not wait; the line says what
// the PingAnswer holds, the data check of a large reply above all
// (reassembly up to 64 KiB).
void net_ping_answer(const PingAnswer* a){
    char from[16];
    ip_int_to_str(a->from, from);
    printf("Ping answer : seq=%u from %s type=%u code=%u ttl=%u bytes=%u data=%s%s\n",
           a->seq, from, a->type, a->code, a->ttl, a->bytes,
           a->type == ICMP_ECHO_REPLY ? (a->data_ok ? "ok" : "BAD") : "-",
           a->mtu ? " (next-hop MTU given)" : "");
}
