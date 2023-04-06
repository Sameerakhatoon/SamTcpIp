#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "Layer2/layer2.h"
#include "Layer3/layer3.h"
#include "Layer4/udp.h"
#include "Layer4/tcp.h"
#include "Layer5/ping.h"
#include "Layer5/http.h"
#include "tap.h"
#include "pcap.h"
#include "cli.h"
#include "comm.h"
#include "graph.h"
#include "net.h"
#include "nwcli.h"

// Forward declarations.
static Node* find_node_by_name(const char* name);
static int   show_topology_handler(int argc, char** argv);
static int   show_node_arp_handler(int argc, char** argv);
static int   show_node_mac_handler(int argc, char** argv);
static int   show_node_route_handler(int argc, char** argv);
static int   run_send_handler(int argc, char** argv);
static int   run_node_resolve_arp_handler(int argc, char** argv);
static int   run_node_ping_handler(int argc, char** argv);
static int   run_node_ping_bad_handler(int argc, char** argv);
static int   run_node_ping_bad_ip_handler(int argc, char** argv);
static int   run_node_udp_handler(int argc, char** argv);
static int   run_node_udp_bad_csum_handler(int argc, char** argv);
static int   run_node_arp_announce_handler(int argc, char** argv);
static int   config_tcp_listen_handler(int argc, char** argv);
static int   config_http_listen_handler(int argc, char** argv);
static int   show_node_tcp_handler(int argc, char** argv);
static int   run_node_tcp_syn_handler(int argc, char** argv);
static int   run_node_tcp_send_handler(int argc, char** argv);
static int   run_node_tcp_close_handler(int argc, char** argv);
static int   run_pcap_start_handler(int argc, char** argv);
static int   run_pcap_stop_handler(int argc, char** argv);
static int   run_tap_open_handler(int argc, char** argv);
static int   run_tap_close_handler(int argc, char** argv);
static int   run_tap_attach_handler(int argc, char** argv);
static int   run_tap_detach_handler(int argc, char** argv);
static int   run_tap_ifup_handler(int argc, char** argv);
static int   run_tap_host_ip_handler(int argc, char** argv);
static int   config_l2mode_handler(int argc, char** argv);
static int   config_route_handler(int argc, char** argv);
static int   config_intf_ip_handler(int argc, char** argv);
void         nwcli_install(Graph* topo);

// The CLI tree only ever needs a single Graph (the topology built at
// startup); stash it so handlers do not need argv.
static Graph* g_topo = 0;

static Node* find_node_by_name(const char* name){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&g_topo->node_list, cur){
        Node* n = graph_glue_to_node(cur);
        if(strncmp(n->node_name, name, NODE_NAME_SIZE) == 0){
            return n;
        }
    } ITERATE_GLTHREAD_END(&g_topo->node_list, cur);
    return 0;
}

static int show_topology_handler(int argc, char** argv){
    (void)argc; (void)argv;
    if(!g_topo){
        fprintf(stderr, "no topology installed\n");
        return 1;
    }
    dump_nw_graph(g_topo);
    return 0;
}

// ch5: `show node <node-name> arp` - dump the per-Node ARP cache.
static int show_node_arp_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "show node arp: expected <node>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    dump_arp_table(NODE_ARP_TABLE(node));
    return 0;
}

// ch6: `show node <node-name> mac` - dump the per-Node mac-learning
// table (only meaningful on a Node operating as an L2 switch).
static int show_node_mac_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "show node mac: expected <node>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    dump_mac_table(NODE_MAC_TABLE(node));
    return 0;
}

// ch8: `show node <node-name> route` - dump the L3 routing table.
static int show_node_route_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "show node route: expected <node>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    dump_rt_table(NODE_RT_TABLE(node));
    return 0;
}

// ch8: `config node <node> route <prefix> <mask> <gw_ip> <oif>` -
// install a static route. gw_ip / oif may be "direct" / "-" to add
// a directly-connected route with no next hop.
static int config_route_handler(int argc, char** argv){
    if(argc != 5){
        fprintf(stderr, "config: expected <node> route <prefix> <mask> <gw_ip> <oif>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    char* prefix = argv[1];
    int   mask   = atoi(argv[2]);
    char* gw     = argv[3];
    char* oif    = argv[4];
    if(strcmp(gw, "direct") == 0 || strcmp(gw, "-") == 0){
        rt_table_add_direct_route(NODE_RT_TABLE(node), prefix, (char)mask);
    } else {
        rt_table_add_route(NODE_RT_TABLE(node), prefix, (char)mask, gw, oif);
    }
    return 0;
}

// ch6: `config node <node> interface <if> l2mode <access|trunk>`.
// Flips the interface to L2 mode and stashes its IP-config flag so
// it can be brought back to L3 later.
// ch19: `config node <node> interface <if> ip <ip> <mask>` -
// reconfigure the simulator-side IP at runtime. The topology
// builder sets initial IPs; ch19 lets us realign R0_re's eth0/0
// with the host-side subnet that ch18's tap host-ip set up.
static int config_intf_ip_handler(int argc, char** argv){
    if(argc != 4){
        fprintf(stderr, "config: expected <node> interface <if> ip <ip> <mask>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    int mask = atoi(argv[3]);
    if(mask < 0 || mask > 32){
        fprintf(stderr, "config interface ip: mask out of range\n");
        return 1;
    }
    if(!node_set_intf_ip_address(node, argv[1], argv[2], (char)mask)){
        fprintf(stderr, "config interface ip: set failed (no such intf? bad ip?)\n");
        return 1;
    }
    printf("Intf ip : %s/%s set to %s/%d\n",
           node->node_name, argv[1], argv[2], mask);
    // ch20: announce the new IP via GARP so peers (including the
    // host kernel on the TAP side) update their ARP caches without
    // waiting for an active resolution.
    Interface* iface = get_node_if_by_name(node, argv[1]);
    if(iface){
        send_gratuitous_arp(node, iface);
    }
    return 0;
}

static int config_l2mode_handler(int argc, char** argv){
    if(argc != 3){
        fprintf(stderr, "config: expected <node> <if> <access|trunk>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    Interface* intf = get_node_if_by_name(node, argv[1]);
    if(!intf){
        fprintf(stderr, "no such interface `%s` on node `%s`\n", argv[1], argv[0]);
        return 1;
    }
    if(strcmp(argv[2], "access") != 0 && strcmp(argv[2], "trunk") != 0){
        fprintf(stderr, "l2mode must be access or trunk\n");
        return 1;
    }
    interface_set_l2_mode(node, intf, argv[2]);
    return 0;
}

// ch4: `run send <node> <if> <payload>`.
static int run_send_handler(int argc, char** argv){
    if(argc != 3){
        fprintf(stderr, "run send: expected <node> <if> <payload>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    Interface* oif = get_node_if_by_name(node, argv[1]);
    if(!oif){
        fprintf(stderr, "no such interface `%s` on node `%s`\n", argv[1], argv[0]);
        return 1;
    }
    int rc = send_pkt_out(argv[2], strlen(argv[2]) + 1, oif);
    if(rc < 0){
        fprintf(stderr, "send_pkt_out failed (rc=%d)\n", rc);
        return 1;
    }
    usleep(100 * 1000);
    return 0;
}

// ch5: `run node <node> resolve-arp <ip>` - trigger an ARP request
// for `<ip>` from `<node>`. The detached receiver thread does the
// rest (reply, table update) before we return to the caller.
static int run_node_resolve_arp_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "run node resolve-arp: expected <node> <ip>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    send_arp_broadcast_request(node, 0, argv[1]);
    // Give the (detached) receiver thread time to process request,
    // send reply, process reply, update ARP table.
    usleep(200 * 1000);
    return 0;
}

// ch10: `run node <node> ping <ip>` - real ping app.
//
// First call to a given dst will ARP-miss (the L3 pipeline drops
// the request, fires a broadcast). To get a deterministic reply
// without forcing the user to manually pre-resolve, we send 3
// pings with sleeps between: #1 seeds the ARP cache, #2/#3 should
// round-trip and print "Ping reply ...".
static int run_node_ping_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "run node ping: expected <node> <ip>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    for(short seq = 1; seq <= 3; seq++){
        ping_send_request(node, argv[1], seq);
        usleep(200 * 1000);
    }
    return 0;
}

// ch11: `run node <node> ping-bad <ip>` - fixture for the
// receiver's RFC 1071 verify path.
//
// Fires three valid pings first so ARP settles + the receiver
// definitely handles ECHO REQUEST correctly, then ONE corrupted
// ping (XORs a bit of the checksum after compute). The receiver
// MUST drop the corrupted one with "ICMP checksum invalid".
static int run_node_ping_bad_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "run node ping-bad: expected <node> <ip>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    for(short seq = 1; seq <= 3; seq++){
        ping_send_request(node, argv[1], seq);
        usleep(200 * 1000);
    }
    // One bad-checksum ping. Receiver MUST drop.
    ping_send_request_bad_checksum(node, argv[1], 99);
    usleep(200 * 1000);
    return 0;
}

// ch12: `run node <node> ping-bad-ip <ip>` - flips an IP-header
// bit on originate so the receiver's IP-csum verify drops the
// packet. Three valid pings first to settle ARP both directions,
// then enable the hook, fire one more ping, disable the hook.
static int run_node_ping_bad_ip_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "run node ping-bad-ip: expected <node> <ip>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    for(short seq = 1; seq <= 3; seq++){
        ping_send_request(node, argv[1], seq);
        usleep(200 * 1000);
    }
    l3_test_force_ip_csum_corruption(true);
    ping_send_request(node, argv[1], 88);
    usleep(200 * 1000);
    l3_test_force_ip_csum_corruption(false);
    return 0;
}

// ch13: `run node <node> udp <ip>` - send a UDP datagram with a
// fixed greeting payload to <ip>:7 (echo port). The receiver
// echoes back to the source port - we use UDP_PRINTER_PORT
// (12345) as src so the reply lands on the printer handler and
// produces a deterministic log line.
//
// Three sends with sleeps for the same ARP-warmup reason ping
// uses three (ARP-miss on first attempt seeds the cache; second
// and third round-trip).
static int run_node_udp_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "run node udp: expected <node> <ip>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, argv[1], &dst_net) != 1){
        fprintf(stderr, "udp: bad ip `%s`\n", argv[1]);
        return 1;
    }
    unsigned int dst_host = htonl(dst_net);
    const char* msg = "hello-from-samtcpip";
    for(int i = 0; i < 3; i++){
        udp_send_pkt(node, dst_host, UDP_PRINTER_PORT, UDP_ECHO_PORT,
                     msg, strlen(msg));
        usleep(200 * 1000);
    }
    return 0;
}

// ch13: `run node <node> udp-bad-csum <ip>`. Same flow as `udp`
// but the test hook flips one bit of the UDP checksum on emit.
// Receiver MUST drop with "UDP recv : ... checksum invalid".
static int run_node_udp_bad_csum_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "run node udp-bad-csum: expected <node> <ip>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, argv[1], &dst_net) != 1){
        fprintf(stderr, "udp-bad-csum: bad ip `%s`\n", argv[1]);
        return 1;
    }
    unsigned int dst_host = htonl(dst_net);
    const char* msg = "hello-from-samtcpip";

    // 3 valid pings to settle ARP. (UDP-only flow would have to
    // wait for ARP on the first packet; ping pre-warms.)
    for(short seq = 1; seq <= 3; seq++){
        ping_send_request(node, argv[1], seq);
        usleep(200 * 1000);
    }
    // 1 corrupted UDP send.
    udp_test_force_csum_corruption(true);
    udp_send_pkt(node, dst_host, UDP_PRINTER_PORT, UDP_ECHO_PORT,
                 msg, strlen(msg));
    usleep(200 * 1000);
    udp_test_force_csum_corruption(false);
    return 0;
}

// ch20: `run node <node> arp-announce` - broadcast a GARP on
// every L3-mode interface. Used by tests + ops to refresh peer
// caches without waiting for active resolution.
static int run_node_arp_announce_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "run node arp-announce: expected <node>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    int sent = 0;
    for(int i = 0; i < MAX_INTF_PER_NODE; i++){
        Interface* iface = node->intf[i];
        if(!iface) continue;
        if(!IS_INTF_L3_MODE(iface)) continue;
        send_gratuitous_arp(node, iface);
        sent++;
    }
    printf("GARP : %s : announced on %d interface(s)\n", node->node_name, sent);
    return 0;
}

// ch22: `config node <node> tcp-listen <port>` - passive open.
static int config_tcp_listen_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "config: expected <node> tcp-listen <port>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    if(port < 1 || port > 65535){
        fprintf(stderr, "tcp-listen: port out of range\n");
        return 1;
    }
    if(!tcp_listen(node, (unsigned short)port)){
        return 1;
    }
    return 0;
}

// ch29: `config node <node> http-listen <port>` - install the
// HTTP hello responder on (node, port).
static int config_http_listen_handler(int argc, char** argv){
    if(argc != 2){
        fprintf(stderr, "config: expected <node> http-listen <port>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    if(port < 1 || port > 65535){
        fprintf(stderr, "http-listen: port out of range\n");
        return 1;
    }
    if(!http_hello_install(node, (unsigned short)port)){
        return 1;
    }
    return 0;
}

// ch22: `show node <node> tcp` - dump TCBs on the node.
static int show_node_tcp_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "show node tcp: expected <node>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    tcp_dump(node);
    return 0;
}

// ch22: `run node <node> tcp-syn <ip> <dport>` - test fixture.
static int run_node_tcp_syn_handler(int argc, char** argv){
    if(argc != 3){
        fprintf(stderr, "run node tcp-syn: expected <node> <ip> <dport>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, argv[1], &dst_net) != 1){
        fprintf(stderr, "tcp-syn: bad ip\n");
        return 1;
    }
    int dport = atoi(argv[2]);
    if(dport < 1 || dport > 65535){
        fprintf(stderr, "tcp-syn: dport out of range\n");
        return 1;
    }
    // src_port: pick a high ephemeral one.
    tcp_send_syn(node, htonl(dst_net), 33333, (unsigned short)dport);
    usleep(200 * 1000);
    return 0;
}

// ch23: `run node <node> tcp-send <ip> <dport> <text>` - send
// data on an existing ESTABLISHED TCB to (dst_ip, dst_port).
static int run_node_tcp_send_handler(int argc, char** argv){
    if(argc != 4){
        fprintf(stderr, "run node tcp-send: expected <node> <ip> <dport> <text>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, argv[1], &dst_net) != 1){
        fprintf(stderr, "tcp-send: bad ip\n");
        return 1;
    }
    int dport = atoi(argv[2]);
    if(dport < 1 || dport > 65535){
        fprintf(stderr, "tcp-send: dport out of range\n");
        return 1;
    }
    if(!tcp_send_data(node, htonl(dst_net), (unsigned short)dport,
                      argv[3], strlen(argv[3]))){
        return 1;
    }
    usleep(200 * 1000);
    return 0;
}

// ch26: `run node <node> tcp-close <ip> <dport>` - initiate
// orderly close on the TCB to (ip, dport).
static int run_node_tcp_close_handler(int argc, char** argv){
    if(argc != 3){
        fprintf(stderr, "run node tcp-close: expected <node> <ip> <dport>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    unsigned int dst_net = 0;
    if(inet_pton(AF_INET, argv[1], &dst_net) != 1){
        fprintf(stderr, "tcp-close: bad ip\n");
        return 1;
    }
    int dport = atoi(argv[2]);
    if(dport < 1 || dport > 65535){
        fprintf(stderr, "tcp-close: dport out of range\n");
        return 1;
    }
    if(!tcp_close(node, htonl(dst_net), (unsigned short)dport)){
        return 1;
    }
    usleep(200 * 1000);
    return 0;
}

// ch28: run pcap start <file> / run pcap stop
static int run_pcap_start_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "run pcap start: expected <file>\n");
        return 1;
    }
    return pcap_open_file(argv[0]) == 0 ? 0 : 1;
}
static int run_pcap_stop_handler(int argc, char** argv){
    (void)argc; (void)argv;
    pcap_close_file();
    return 0;
}

// ch14: `run tap open <name>` - opens /dev/net/tun with
// IFF_TAP | IFF_NO_PI and stashes the fd globally. Calling twice
// without close leaks the previous fd; that's an operator error
// the simulator doesn't try to recover from.
static int g_tap_fd = -1;
static int run_tap_open_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "run tap open: expected <ifname>\n");
        return 1;
    }
    if(g_tap_fd >= 0){
        fprintf(stderr, "run tap open: a TAP fd is already open (close first)\n");
        return 1;
    }
    g_tap_fd = tap_open(argv[0]);
    if(g_tap_fd < 0){
        // tap_open already printed a diagnostic.
        return 1;
    }
    return 0;
}

// ch14: `run tap close` - closes the stashed fd. No-op if -1.
static int run_tap_close_handler(int argc, char** argv){
    (void)argc; (void)argv;
    tap_close(g_tap_fd);
    g_tap_fd = -1;
    printf("TAP closed\n");
    return 0;
}

// ch15: `run tap attach <node> <ifname> <iif>` - opens the TAP
// AND spawns the recv thread bound to (node, iif). Frames coming
// out of the kernel's TAP-other-end get fed straight into
// pkt_receive as if they had arrived on `iif`.
static int run_tap_attach_handler(int argc, char** argv){
    if(argc != 3){
        fprintf(stderr, "run tap attach: expected <node> <ifname> <iif>\n");
        return 1;
    }
    Node* node = find_node_by_name(argv[0]);
    if(!node){
        fprintf(stderr, "no such node `%s`\n", argv[0]);
        return 1;
    }
    if(tap_attach(node, argv[1], argv[2]) < 0){
        // tap_attach already printed the diagnostic.
        return 1;
    }
    return 0;
}

// ch15: `run tap detach` - stops the recv thread, closes the fd.
static int run_tap_detach_handler(int argc, char** argv){
    (void)argc; (void)argv;
    tap_detach();
    return 0;
}

// ch18: `run tap ifup <ifname>` - flip IFF_UP on the kernel-side TAP.
static int run_tap_ifup_handler(int argc, char** argv){
    if(argc != 1){
        fprintf(stderr, "run tap ifup: expected <ifname>\n");
        return 1;
    }
    if(tap_ifup(argv[0]) < 0){
        return 1;
    }
    return 0;
}

// ch18: `run tap host-ip <ifname> <ip> <mask-bits>` - assign the
// kernel side of the TAP its IP, so the host can route to us.
static int run_tap_host_ip_handler(int argc, char** argv){
    if(argc != 3){
        fprintf(stderr, "run tap host-ip: expected <ifname> <ip> <mask-bits>\n");
        return 1;
    }
    int mask = atoi(argv[2]);
    if(tap_set_host_ip(argv[0], argv[1], mask) < 0){
        return 1;
    }
    return 0;
}

// ---- command tree --------------------------------------------------------
// Children arrays are NULL-terminated. Built bottom-up so each
// parent's child pointer table is in scope.

// show topology
static CliCmd cmd_show_topology = {
    .name     = "topology",
    .handler  = show_topology_handler,
    .help     = "dump the loaded topology with L2/L3 properties",
};

// show node <name> arp
static CliCmd cmd_show_node_arp = {
    .name     = "arp",
    .handler  = show_node_arp_handler,
    .help     = "dump the node's ARP table",
};
// show node <name> mac
static CliCmd cmd_show_node_mac = {
    .name     = "mac",
    .handler  = show_node_mac_handler,
    .help     = "dump the node's mac-learning table",
};
// show node <name> route
static CliCmd cmd_show_node_route = {
    .name     = "route",
    .handler  = show_node_route_handler,
    .help     = "dump the node's L3 routing table",
};
// show node <name> tcp (ch22)
static CliCmd cmd_show_node_tcp = {
    .name     = "tcp",
    .handler  = show_node_tcp_handler,
    .help     = "dump the node's TCB list",
};
static CliCmd* show_node_name_children[] = {
    &cmd_show_node_arp,
    &cmd_show_node_mac,
    &cmd_show_node_route,
    &cmd_show_node_tcp,
    0,
};

static CliCmd cmd_show_node_name = {
    .name     = "<node-name>",
    .capture  = true,
    .help     = "node name (e.g. R0_re)",
    .children = show_node_name_children,
};
static CliCmd* show_node_children[] = { &cmd_show_node_name, 0 };

static CliCmd cmd_show_node = {
    .name     = "node",
    .help     = "show node <name> <subcommand>",
    .children = show_node_children,
};

static CliCmd* show_children[] = {
    &cmd_show_topology,
    &cmd_show_node,
    0,
};

static CliCmd cmd_show = {
    .name     = "show",
    .help     = "show: inspect runtime state",
    .children = show_children,
};

// run send <node> <if> <payload>
static CliCmd cmd_run_send_payload = {
    .name     = "<payload>",
    .capture  = true,
    .handler  = run_send_handler,
    .help     = "payload bytes (cstring)",
};
static CliCmd* run_send_payload_children[] = { &cmd_run_send_payload, 0 };

static CliCmd cmd_run_send_if = {
    .name     = "<if-name>",
    .capture  = true,
    .help     = "interface name (e.g. eth0/0)",
    .children = run_send_payload_children,
};
static CliCmd* run_send_if_children[] = { &cmd_run_send_if, 0 };

static CliCmd cmd_run_send_node = {
    .name     = "<node-name>",
    .capture  = true,
    .help     = "node name (e.g. R0_re)",
    .children = run_send_if_children,
};
static CliCmd* run_send_node_children[] = { &cmd_run_send_node, 0 };

static CliCmd cmd_run_send = {
    .name     = "send",
    .help     = "send <node> <if> <payload>: emit a packet out an intf",
    .children = run_send_node_children,
};

// run node <name> resolve-arp <ip>
static CliCmd cmd_run_node_resolve_ip = {
    .name     = "<ip>",
    .capture  = true,
    .handler  = run_node_resolve_arp_handler,
    .help     = "IP address to resolve via ARP",
};
static CliCmd* run_node_resolve_ip_children[] = { &cmd_run_node_resolve_ip, 0 };

static CliCmd cmd_run_node_resolve = {
    .name     = "resolve-arp",
    .help     = "send an ARP broadcast for <ip>",
    .children = run_node_resolve_ip_children,
};

// run node <name> ping <ip>
static CliCmd cmd_run_node_ping_ip = {
    .name     = "<ip>",
    .capture  = true,
    .handler  = run_node_ping_handler,
    .help     = "destination IP to ping",
};
static CliCmd* run_node_ping_ip_children[] = { &cmd_run_node_ping_ip, 0 };

static CliCmd cmd_run_node_ping = {
    .name     = "ping",
    .help     = "originate an IP datagram with payload `ping` to <ip>",
    .children = run_node_ping_ip_children,
};

// ch11: run node <name> ping-bad <ip>
static CliCmd cmd_run_node_ping_bad_ip = {
    .name     = "<ip>",
    .capture  = true,
    .handler  = run_node_ping_bad_handler,
    .help     = "destination IP; 3 valid pings then 1 with corrupted ICMP csum",
};
static CliCmd* run_node_ping_bad_ip_children[] = { &cmd_run_node_ping_bad_ip, 0 };
static CliCmd cmd_run_node_ping_bad = {
    .name     = "ping-bad",
    .help     = "ch11 fixture: 3 valid pings + 1 with bad ICMP checksum",
    .children = run_node_ping_bad_ip_children,
};

// ch12: run node <name> ping-bad-ip <ip>
static CliCmd cmd_run_node_ping_bad_ip2_ip = {
    .name     = "<ip>",
    .capture  = true,
    .handler  = run_node_ping_bad_ip_handler,
    .help     = "destination IP; 3 valid pings then 1 with corrupted IP csum",
};
static CliCmd* run_node_ping_bad_ip2_ip_children[] = { &cmd_run_node_ping_bad_ip2_ip, 0 };
static CliCmd cmd_run_node_ping_bad_ip2 = {
    .name     = "ping-bad-ip",
    .help     = "ch12 fixture: 3 valid pings + 1 with bad IP checksum",
    .children = run_node_ping_bad_ip2_ip_children,
};

// ch13: run node <name> udp <ip>
static CliCmd cmd_run_node_udp_ip = {
    .name     = "<ip>",
    .capture  = true,
    .handler  = run_node_udp_handler,
    .help     = "destination IP; sends UDP greeting to port 7 (echo)",
};
static CliCmd* run_node_udp_ip_children[] = { &cmd_run_node_udp_ip, 0 };
static CliCmd cmd_run_node_udp = {
    .name     = "udp",
    .help     = "originate a UDP datagram with greeting payload",
    .children = run_node_udp_ip_children,
};

// ch13: run node <name> udp-bad-csum <ip>
static CliCmd cmd_run_node_udp_bad_ip = {
    .name     = "<ip>",
    .capture  = true,
    .handler  = run_node_udp_bad_csum_handler,
    .help     = "destination IP; 3 valid pings then 1 UDP with bad checksum",
};
static CliCmd* run_node_udp_bad_ip_children[] = { &cmd_run_node_udp_bad_ip, 0 };
static CliCmd cmd_run_node_udp_bad = {
    .name     = "udp-bad-csum",
    .help     = "ch13 fixture: 3 valid pings + 1 UDP with bad checksum",
    .children = run_node_udp_bad_ip_children,
};

// ch20: run node <name> arp-announce
static CliCmd cmd_run_node_arp_announce = {
    .name     = "arp-announce",
    .handler  = run_node_arp_announce_handler,
    .help     = "broadcast a GARP on every L3 interface of <node>",
};

// ch22: run node <name> tcp-syn <ip> <dport>
static CliCmd cmd_run_node_tcp_syn_dport = {
    .name     = "<dport>",
    .capture  = true,
    .handler  = run_node_tcp_syn_handler,
    .help     = "destination TCP port",
};
static CliCmd* run_node_tcp_syn_dport_children[] = { &cmd_run_node_tcp_syn_dport, 0 };
static CliCmd cmd_run_node_tcp_syn_ip = {
    .name     = "<ip>",
    .capture  = true,
    .help     = "destination IP",
    .children = run_node_tcp_syn_dport_children,
};
static CliCmd* run_node_tcp_syn_ip_children[] = { &cmd_run_node_tcp_syn_ip, 0 };
static CliCmd cmd_run_node_tcp_syn = {
    .name     = "tcp-syn",
    .help     = "ch22 fixture: hand-build + send a TCP SYN",
    .children = run_node_tcp_syn_ip_children,
};

// ch23: run node <name> tcp-send <ip> <dport> <text>
static CliCmd cmd_run_node_tcp_send_text = {
    .name     = "<text>",
    .capture  = true,
    .handler  = run_node_tcp_send_handler,
    .help     = "payload string to send",
};
static CliCmd* run_node_tcp_send_text_children[] = { &cmd_run_node_tcp_send_text, 0 };
static CliCmd cmd_run_node_tcp_send_dport = {
    .name     = "<dport>",
    .capture  = true,
    .help     = "destination TCP port",
    .children = run_node_tcp_send_text_children,
};
static CliCmd* run_node_tcp_send_dport_children[] = { &cmd_run_node_tcp_send_dport, 0 };
static CliCmd cmd_run_node_tcp_send_ip = {
    .name     = "<ip>",
    .capture  = true,
    .help     = "destination IP",
    .children = run_node_tcp_send_dport_children,
};
static CliCmd* run_node_tcp_send_ip_children[] = { &cmd_run_node_tcp_send_ip, 0 };
static CliCmd cmd_run_node_tcp_send = {
    .name     = "tcp-send",
    .help     = "ch23 fixture: send data on an established TCB",
    .children = run_node_tcp_send_ip_children,
};

// ch26: run node <name> tcp-close <ip> <dport>
static CliCmd cmd_run_node_tcp_close_dport = {
    .name     = "<dport>",
    .capture  = true,
    .handler  = run_node_tcp_close_handler,
    .help     = "remote TCP port",
};
static CliCmd* run_node_tcp_close_dport_children[] = { &cmd_run_node_tcp_close_dport, 0 };
static CliCmd cmd_run_node_tcp_close_ip = {
    .name     = "<ip>",
    .capture  = true,
    .help     = "remote IP",
    .children = run_node_tcp_close_dport_children,
};
static CliCmd* run_node_tcp_close_ip_children[] = { &cmd_run_node_tcp_close_ip, 0 };
static CliCmd cmd_run_node_tcp_close = {
    .name     = "tcp-close",
    .help     = "initiate orderly close on TCB to (ip, dport)",
    .children = run_node_tcp_close_ip_children,
};

static CliCmd* run_node_name_children[] = {
    &cmd_run_node_resolve,
    &cmd_run_node_ping,
    &cmd_run_node_ping_bad,
    &cmd_run_node_ping_bad_ip2,
    &cmd_run_node_udp,
    &cmd_run_node_udp_bad,
    &cmd_run_node_arp_announce,
    &cmd_run_node_tcp_syn,
    &cmd_run_node_tcp_send,
    &cmd_run_node_tcp_close,
    0,
};

static CliCmd cmd_run_node_name = {
    .name     = "<node-name>",
    .capture  = true,
    .help     = "node name (e.g. R0_re)",
    .children = run_node_name_children,
};
static CliCmd* run_node_children[] = { &cmd_run_node_name, 0 };

static CliCmd cmd_run_node = {
    .name     = "node",
    .help     = "run node <name> <subcommand>",
    .children = run_node_children,
};

// ch14: run tap open <ifname> / run tap close
static CliCmd cmd_run_tap_open_ifname = {
    .name     = "<ifname>",
    .capture  = true,
    .handler  = run_tap_open_handler,
    .help     = "TAP interface name (e.g. samtap0); empty -> kernel allocates",
};
static CliCmd* run_tap_open_ifname_children[] = { &cmd_run_tap_open_ifname, 0 };
static CliCmd cmd_run_tap_open = {
    .name     = "open",
    .help     = "open a TAP interface (needs CAP_NET_ADMIN)",
    .children = run_tap_open_ifname_children,
};

static CliCmd cmd_run_tap_close = {
    .name     = "close",
    .handler  = run_tap_close_handler,
    .help     = "close the stashed TAP fd",
};

// ch15: run tap attach <node> <ifname> <iif>
static CliCmd cmd_run_tap_attach_iif = {
    .name     = "<iif>",
    .capture  = true,
    .handler  = run_tap_attach_handler,
    .help     = "interface name on <node> the TAP plays the role of (e.g. eth0/0)",
};
static CliCmd* run_tap_attach_iif_children[] = { &cmd_run_tap_attach_iif, 0 };
static CliCmd cmd_run_tap_attach_ifname = {
    .name     = "<ifname>",
    .capture  = true,
    .help     = "TAP interface name (kernel-side, e.g. samtap0)",
    .children = run_tap_attach_iif_children,
};
static CliCmd* run_tap_attach_ifname_children[] = { &cmd_run_tap_attach_ifname, 0 };
static CliCmd cmd_run_tap_attach_node = {
    .name     = "<node>",
    .capture  = true,
    .help     = "Node to bind TAP to (the userspace stack's home)",
    .children = run_tap_attach_ifname_children,
};
static CliCmd* run_tap_attach_node_children[] = { &cmd_run_tap_attach_node, 0 };
static CliCmd cmd_run_tap_attach = {
    .name     = "attach",
    .help     = "open TAP + spawn recv thread bound to (node, iif)",
    .children = run_tap_attach_node_children,
};

static CliCmd cmd_run_tap_detach = {
    .name     = "detach",
    .handler  = run_tap_detach_handler,
    .help     = "stop the recv thread + close the TAP fd",
};

// ch18: run tap ifup <ifname>
static CliCmd cmd_run_tap_ifup_ifname = {
    .name     = "<ifname>",
    .capture  = true,
    .handler  = run_tap_ifup_handler,
    .help     = "TAP interface name to bring UP",
};
static CliCmd* run_tap_ifup_ifname_children[] = { &cmd_run_tap_ifup_ifname, 0 };
static CliCmd cmd_run_tap_ifup = {
    .name     = "ifup",
    .help     = "set IFF_UP on the kernel-side TAP interface",
    .children = run_tap_ifup_ifname_children,
};

// ch18: run tap host-ip <ifname> <ip> <mask-bits>
static CliCmd cmd_run_tap_host_ip_mask = {
    .name     = "<mask-bits>",
    .capture  = true,
    .handler  = run_tap_host_ip_handler,
    .help     = "netmask in CIDR bits (0..32)",
};
static CliCmd* run_tap_host_ip_mask_children[] = { &cmd_run_tap_host_ip_mask, 0 };
static CliCmd cmd_run_tap_host_ip_ip = {
    .name     = "<ip>",
    .capture  = true,
    .help     = "dotted-quad IP for the kernel-side TAP",
    .children = run_tap_host_ip_mask_children,
};
static CliCmd* run_tap_host_ip_ip_children[] = { &cmd_run_tap_host_ip_ip, 0 };
static CliCmd cmd_run_tap_host_ip_if = {
    .name     = "<ifname>",
    .capture  = true,
    .help     = "TAP interface name",
    .children = run_tap_host_ip_ip_children,
};
static CliCmd* run_tap_host_ip_if_children[] = { &cmd_run_tap_host_ip_if, 0 };
static CliCmd cmd_run_tap_host_ip = {
    .name     = "host-ip",
    .help     = "assign IP/mask to kernel-side TAP (replaces sudo ip addr add)",
    .children = run_tap_host_ip_if_children,
};

static CliCmd* run_tap_children[] = {
    &cmd_run_tap_open,
    &cmd_run_tap_close,
    &cmd_run_tap_attach,
    &cmd_run_tap_detach,
    &cmd_run_tap_ifup,
    &cmd_run_tap_host_ip,
    0,
};
static CliCmd cmd_run_tap = {
    .name     = "tap",
    .help     = "TAP device primitives (ch14)",
    .children = run_tap_children,
};

// ch28: run pcap start <file> / run pcap stop
static CliCmd cmd_run_pcap_start_file = {
    .name     = "<file>",
    .capture  = true,
    .handler  = run_pcap_start_handler,
    .help     = "output pcap file path",
};
static CliCmd* run_pcap_start_file_children[] = { &cmd_run_pcap_start_file, 0 };
static CliCmd cmd_run_pcap_start = {
    .name     = "start",
    .help     = "begin capturing every frame to <file>",
    .children = run_pcap_start_file_children,
};
static CliCmd cmd_run_pcap_stop = {
    .name     = "stop",
    .handler  = run_pcap_stop_handler,
    .help     = "stop the active capture",
};
static CliCmd* run_pcap_children[] = {
    &cmd_run_pcap_start,
    &cmd_run_pcap_stop,
    0,
};
static CliCmd cmd_run_pcap = {
    .name     = "pcap",
    .help     = "ch28 packet capture controls",
    .children = run_pcap_children,
};

static CliCmd* run_children[] = {
    &cmd_run_send,
    &cmd_run_node,
    &cmd_run_tap,
    &cmd_run_pcap,
    0,
};

static CliCmd cmd_run = {
    .name     = "run",
    .help     = "run: perform live actions",
    .children = run_children,
};

// config node <node> interface <if> l2mode <access|trunk>
static CliCmd cmd_config_l2mode_val = {
    .name     = "<access|trunk>",
    .capture  = true,
    .handler  = config_l2mode_handler,
    .help     = "access or trunk",
};
static CliCmd* config_l2mode_val_children[] = { &cmd_config_l2mode_val, 0 };

static CliCmd cmd_config_l2mode = {
    .name     = "l2mode",
    .help     = "set L2 mode on the interface",
    .children = config_l2mode_val_children,
};

// ch19: config node <node> interface <if> ip <ip> <mask>
static CliCmd cmd_config_intf_ip_mask = {
    .name     = "<mask>",
    .capture  = true,
    .handler  = config_intf_ip_handler,
    .help     = "netmask bits 0..32",
};
static CliCmd* config_intf_ip_mask_children[] = { &cmd_config_intf_ip_mask, 0 };
static CliCmd cmd_config_intf_ip_ip = {
    .name     = "<ip>",
    .capture  = true,
    .help     = "dotted-quad IP",
    .children = config_intf_ip_mask_children,
};
static CliCmd* config_intf_ip_ip_children[] = { &cmd_config_intf_ip_ip, 0 };
static CliCmd cmd_config_intf_ip = {
    .name     = "ip",
    .help     = "set the interface IP at runtime",
    .children = config_intf_ip_ip_children,
};

static CliCmd* config_if_name_children[] = { &cmd_config_l2mode, &cmd_config_intf_ip, 0 };

static CliCmd cmd_config_if_name = {
    .name     = "<if-name>",
    .capture  = true,
    .help     = "interface name",
    .children = config_if_name_children,
};
static CliCmd* config_interface_children[] = { &cmd_config_if_name, 0 };

static CliCmd cmd_config_interface = {
    .name     = "interface",
    .help     = "interface <name> <subcommand>",
    .children = config_interface_children,
};
// config node <node> route <prefix> <mask> <gw> <oif>
static CliCmd cmd_config_route_oif = {
    .name     = "<oif>",
    .capture  = true,
    .handler  = config_route_handler,
    .help     = "outgoing interface (or `-` for direct)",
};
static CliCmd* config_route_oif_children[] = { &cmd_config_route_oif, 0 };

static CliCmd cmd_config_route_gw = {
    .name     = "<gw>",
    .capture  = true,
    .help     = "next-hop IP (or `direct` for directly-connected)",
    .children = config_route_oif_children,
};
static CliCmd* config_route_gw_children[] = { &cmd_config_route_gw, 0 };

static CliCmd cmd_config_route_mask = {
    .name     = "<mask>",
    .capture  = true,
    .help     = "prefix length 0..32",
    .children = config_route_gw_children,
};
static CliCmd* config_route_mask_children[] = { &cmd_config_route_mask, 0 };

static CliCmd cmd_config_route_prefix = {
    .name     = "<prefix>",
    .capture  = true,
    .help     = "destination prefix (dotted-quad)",
    .children = config_route_mask_children,
};
static CliCmd* config_route_prefix_children[] = { &cmd_config_route_prefix, 0 };

static CliCmd cmd_config_route = {
    .name     = "route",
    .help     = "route <prefix> <mask> <gw> <oif>",
    .children = config_route_prefix_children,
};

// ch22: config node <node> tcp-listen <port>
static CliCmd cmd_config_tcp_listen_port = {
    .name     = "<port>",
    .capture  = true,
    .handler  = config_tcp_listen_handler,
    .help     = "TCP port to listen on",
};
static CliCmd* config_tcp_listen_port_children[] = { &cmd_config_tcp_listen_port, 0 };
static CliCmd cmd_config_tcp_listen = {
    .name     = "tcp-listen",
    .help     = "install a passive TCP socket on <port>",
    .children = config_tcp_listen_port_children,
};

// ch29: config node <node> http-listen <port>
static CliCmd cmd_config_http_listen_port = {
    .name     = "<port>",
    .capture  = true,
    .handler  = config_http_listen_handler,
    .help     = "HTTP port to listen on",
};
static CliCmd* config_http_listen_port_children[] = { &cmd_config_http_listen_port, 0 };
static CliCmd cmd_config_http_listen = {
    .name     = "http-listen",
    .help     = "install the hello-world HTTP responder on <port>",
    .children = config_http_listen_port_children,
};

static CliCmd* config_node_name_children[] = {
    &cmd_config_interface,
    &cmd_config_route,
    &cmd_config_tcp_listen,
    &cmd_config_http_listen,
    0,
};

static CliCmd cmd_config_node_name = {
    .name     = "<node-name>",
    .capture  = true,
    .help     = "node name",
    .children = config_node_name_children,
};
static CliCmd* config_node_children[] = { &cmd_config_node_name, 0 };

static CliCmd cmd_config_node = {
    .name     = "node",
    .help     = "config node <name> <subcommand>",
    .children = config_node_children,
};

static CliCmd* config_children[] = {
    &cmd_config_node,
    0,
};

static CliCmd cmd_config = {
    .name     = "config",
    .help     = "config: change device state",
    .children = config_children,
};

static CliCmd* root_children[] = {
    &cmd_show,
    &cmd_run,
    &cmd_config,
    0,
};

static CliCmd cmd_root = {
    .name     = "<root>",
    .help     = "root",
    .children = root_children,
};

void nwcli_install(Graph* topo){
    g_topo = topo;
    cli_set_root(&cmd_root);
    ping_register();
    udp_register();
    udp_install_default_handlers(topo);
    tcp_register();
    network_start_pkt_receiver_thread(topo);
    usleep(50 * 1000);
}
