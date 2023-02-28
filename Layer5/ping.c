#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "../graph.h"
#include "../net.h"
#include "../Layer3/layer3.h"
#include "ping.h"

// Forward declarations.
static void ping_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                      char* payload, size_t payload_size);
void        ping_register(void);
void        ping_send_request(Node* node, char* dst_ip_str, short seq);

static void ping_recv(Node* node, Interface* iif, IpHdr* ip_hdr,
                      char* payload, size_t payload_size){
    (void)iif;
    if(payload_size < sizeof(PingMsg)){
        printf("Ping recv : %s : runt msg, %zu bytes\n",
               node->node_name, payload_size);
        return;
    }
    PingMsg* msg = (PingMsg*)payload;

    // src_ip on the wire is in host byte order (our convention).
    char src_str[16];
    unsigned int net = htonl(ip_hdr->src_ip);
    inet_ntop(AF_INET, &net, src_str, 16);
    src_str[15] = '\0';

    if(msg->type == PING_REQ){
        // Echo: build a REPLY back to the originator. Use the
        // src_ip from the inbound IP header as our destination so
        // an unresolved sender's identity is preserved through the
        // round-trip.
        PingMsg reply = {0};
        reply.type      = PING_REPLY;
        reply.seq       = msg->seq;
        reply.origin_ip = msg->origin_ip;
        printf("Ping recv : %s : REQ seq=%d from %s, sending REPLY\n",
               node->node_name, msg->seq, src_str);
        demote_packet_to_layer3(node, (char*)&reply, sizeof(reply),
                                PING_PROTO, ip_hdr->src_ip);
        return;
    }
    if(msg->type == PING_REPLY){
        printf("Ping reply : %s : seq=%d from %s\n",
               node->node_name, msg->seq, src_str);
        return;
    }
    printf("Ping recv : %s : unknown type %d\n", node->node_name, msg->type);
}

void ping_register(void){
    l3_register_l4_handler(PING_PROTO, ping_recv);
}

void ping_send_request(Node* node, char* dst_ip_str, short seq){
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, dst_ip_str, &dst_net) != 1){
        printf("Ping : %s : bad ip `%s`\n", node->node_name, dst_ip_str);
        return;
    }
    unsigned int dst_host = htonl(dst_net);

    PingMsg req = {0};
    req.type = PING_REQ;
    req.seq  = seq;
    if(node->node_nw_prop.is_lb_addr_config){
        unsigned int src_net = 0;
        inet_pton(AF_INET, NODE_LO_ADDR(node), &src_net);
        req.origin_ip = htonl(src_net);
    }
    demote_packet_to_layer3(node, (char*)&req, sizeof(req),
                            PING_PROTO, dst_host);
}
