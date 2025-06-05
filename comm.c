#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "comm.h"
#include "graph.h"
#include "pcap.h"
#include "tap.h"
#include "Layer4/tcp.h"

// Forward declarations.
static unsigned int get_next_udp_port_number(void);
static int          _send_pkt_out(int sock_fd, char* pkt_data, size_t pkt_size,
                                  unsigned int dst_udp_port_no);
static void         _pkt_receive(Node* receiving_node, char* pkt_with_aux,
                                 size_t pkt_size);
static void*        _network_start_pkt_receiver_thread(void* arg);
void                init_udp_socket(Node* node);
void                network_start_pkt_receiver_thread(Graph* topo);
int                 send_pkt_out(char* pkt, size_t pkt_size, Interface* oif);
int                 send_pkt_flood(Node* node, Interface* exempted_intf, char* pkt, size_t pkt_size);
int                 pkt_receive(Node* node, Interface* iif, char* pkt, size_t pkt_size);
static bool         comm_drop_this(char* pkt, size_t pkt_size, Interface* oif);

// Hand-off to the Layer 2 frame receiver - defined in layer2.c.
extern void layer2_frame_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size);

// Monotonic port counter. First node gets 40000.
static unsigned int udp_port_number = 40000;

static unsigned int get_next_udp_port_number(void){
    return udp_port_number++;
}

// Wire a UDP socket onto a Node and bind it. Idempotent: if the
// Node already has a port the second call is a no-op so the test
// driver can keep calling without thinking about ordering.
//
// Quirk: the source material assigns the port without htons() and
// binds it raw. Both ends do the same so the kernel keeps the bits
// consistent. Preserved verbatim to stay faithful to the reference.
void init_udp_socket(Node* node){
    if(node->udp_port_number){
        return;
    }
    node->udp_port_number = get_next_udp_port_number();

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(fd == -1){
        printf("Socket Creation Failed for node %s\n", node->node_name);
        return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = node->udp_port_number;   // raw, see comment above
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1){
        printf("Error : socket bind failed for Node %s\n", node->node_name);
        close(fd);
        node->udp_port_number = 0;
        return;
    }
    node->udp_sock_fd = fd;
}

// Static scratch buffer used by the (single) receiver thread. The
// sender's is on its stack (send_pkt_out): the CLI, the receiver
// thread and the stack timer thread all send, and a shared
// buffer let one overwrite another's frame and aux header.
static char recv_buffer[MAX_PACKET_BUFFER_SIZE];

// Strip the IF_NAME_SIZE aux header from the front of an incoming
// datagram, look up the matching local Interface by name, and
// hand the payload up to pkt_receive.
static void _pkt_receive(Node* receiving_node, char* pkt_with_aux, size_t pkt_size){
    char*      recv_intf_name = pkt_with_aux;
    Interface* iif            = get_node_if_by_name(receiving_node, recv_intf_name);
    if(!iif){
        printf("Error : Pkt recvd on unknown interface `%s` on node %s\n",
               recv_intf_name, receiving_node->node_name);
        return;
    }
    pkt_receive(receiving_node, iif,
                pkt_with_aux + IF_NAME_SIZE,
                pkt_size - IF_NAME_SIZE);
}

// Single thread fan-in: select() across every Node's bound socket,
// recvfrom whichever one has data, dispatch via _pkt_receive.
static void* _network_start_pkt_receiver_thread(void* arg){
    Graph*    topo = (Graph*)arg;
    GlThread* curr = 0;
    fd_set    active_set;
    fd_set    backup_set;
    int       sock_max_fd = 0;

    FD_ZERO(&active_set);
    FD_ZERO(&backup_set);

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){
        Node* node = graph_glue_to_node(curr);
        if(!node->udp_sock_fd){
            continue;
        }
        if(node->udp_sock_fd > sock_max_fd){
            sock_max_fd = node->udp_sock_fd;
        }
        FD_SET(node->udp_sock_fd, &backup_set);
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);

    for(;;){
        memcpy(&active_set, &backup_set, sizeof(fd_set));
        select(sock_max_fd + 1, &active_set, 0, 0, 0);

        ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){
            Node* node = graph_glue_to_node(curr);
            if(FD_ISSET(node->udp_sock_fd, &active_set)){
                struct sockaddr_in src_addr;
                socklen_t          addr_len = sizeof(src_addr);
                memset(recv_buffer, 0, MAX_PACKET_BUFFER_SIZE);
                ssize_t bytes = recvfrom(node->udp_sock_fd, recv_buffer,
                                         MAX_PACKET_BUFFER_SIZE, 0,
                                         (struct sockaddr*)&src_addr, &addr_len);
                if(bytes > 0){
                    _pkt_receive(node, recv_buffer, (size_t)bytes);
                }
            }
        } ITERATE_GLTHREAD_END(&topo->node_list, curr);
    }
    return 0;
}

void network_start_pkt_receiver_thread(Graph* topo){
    pthread_attr_t attr;
    pthread_t      tid;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, _network_start_pkt_receiver_thread, topo);
    pthread_attr_destroy(&attr);
}

static int _send_pkt_out(int sock_fd, char* pkt_data, size_t pkt_size,
                         unsigned int dst_udp_port_no){
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = dst_udp_port_no;   // raw - see init_udp_socket
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return (int)sendto(sock_fd, pkt_data, pkt_size, 0,
                       (struct sockaddr*)&dest, sizeof(dest));
}

// Send `pkt` out of `oif`. Resolves the peer Node and its bound UDP
// port, prepends the *peer-side* interface name as aux info so the
// receiver knows which port the frame came in on, then sendto's.
int send_pkt_out(char* pkt, size_t pkt_size, Interface* oif){
    int rc = -1;
    if(pkt_size + IF_NAME_SIZE > MAX_PACKET_BUFFER_SIZE){
        return -1;
    }
    if(comm_drop_this(pkt, pkt_size, oif)){
        return 0;                       // test loss
    }
    // ch28: capture egress frame.
    pcap_dump_frame(pkt, pkt_size);

    // ch16: TAP egress. When the oif is the TAP-attached interface,
    // the wire is the kernel's TAP device, not the simulator's UDP
    // loopback. We write the raw frame directly; no peer-side aux
    // header (TAP has IFF_NO_PI set).
    if(tap_is_attached_iif(oif)){
        long n = tap_write_frame(pkt, pkt_size);
        return n > 0 ? 0 : -1;
    }
    Node* nbr_node = get_nbr_node(oif);
    if(!nbr_node){
        return -1;
    }
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0){
        printf("Error : Sending socket Creation failed , errno = %d\n", errno);
        return -1;
    }

    // The aux header carries the *receiver's* interface name (the
    // one on the other end of this link), so the receiver thread
    // can identify which local Interface the frame arrived on.
    Interface* peer_intf = (&oif->link->intf1 == oif)
                         ? &oif->link->intf2
                         : &oif->link->intf1;

    char send_buffer[MAX_PACKET_BUFFER_SIZE];
    memset(send_buffer, 0, MAX_PACKET_BUFFER_SIZE);
    strncpy(send_buffer, peer_intf->if_name, IF_NAME_SIZE);
    send_buffer[IF_NAME_SIZE - 1] = '\0';
    memcpy(send_buffer + IF_NAME_SIZE, pkt, pkt_size);

    rc = _send_pkt_out(sock, send_buffer, pkt_size + IF_NAME_SIZE,
                       nbr_node->udp_port_number);
    close(sock);
    return rc;
}

int send_pkt_flood(Node* node, Interface* exempted_intf, char* pkt, size_t pkt_size){
    int rc = 0;
    for(int i = 0; i < MAX_INTF_PER_NODE; i++){
        Interface* intf = node->intf[i];
        if(!intf){
            break;
        }
        if(intf == exempted_intf){
            continue;
        }
        int one = send_pkt_out(pkt, pkt_size, intf);
        if(one < 0){
            rc = one;
        }
    }
    return rc;
}

// ch17: ingress lock.
//
// Two recv threads now feed pkt_receive: the UDP-loopback fan-in
// (ch4) and the TAP recv thread (ch15). They can land on the same
// Node concurrently. The L2 + L3 paths walk shared per-Node tables
// (ARP cache, MAC table, RT table) that the course built without
// any locking - because there was only one recv thread.
//
// Cheapest correct fix: a single recursive mutex around pkt_receive
// entry. Recursive because the L2 ingress can synchronously call
// send_pkt_out, which in turn may need state we want stable; we'd
// rather not invent a per-table lock-order today. Single because
// our throughput target is "manual ping", not millions of pps.
//
// This is needed for curl-both-ways. Without it
// the receive path races as soon as the TAP fires a frame while
// the simulator wire is also delivering one. One lock for the whole
// stack is enough at this scale (ch17).
static pthread_mutex_t       g_pkt_recv_mtx;
static pthread_once_t        g_pkt_recv_mtx_once = PTHREAD_ONCE_INIT;
static void init_pkt_recv_mtx(void){
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_pkt_recv_mtx, &attr);
    pthread_mutexattr_destroy(&attr);
}

// The stack timer takes the same lock as ingress.
void net_stack_lock(void){
    pthread_once(&g_pkt_recv_mtx_once, init_pkt_recv_mtx);
    pthread_mutex_lock(&g_pkt_recv_mtx);
}

void net_stack_unlock(void){
    pthread_mutex_unlock(&g_pkt_recv_mtx);
}

int pkt_receive(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    pthread_once(&g_pkt_recv_mtx_once, init_pkt_recv_mtx);
    pthread_mutex_lock(&g_pkt_recv_mtx);
    // ch28: capture ingress frame.
    pcap_dump_frame(pkt, pkt_size);
    layer2_frame_recv(node, iif, pkt, pkt_size);
    pthread_mutex_unlock(&g_pkt_recv_mtx);
    return 0;
}

// ---- the stack timer -------------------------------------
//
// SamOS runs tcp_timer (retransmission, TIME_WAIT, orphans) from its
// 100 Hz kernel tick (net/net.c, net_stack_timer). Here a detached
// thread does the same every NET_TIMER_TICK_MS, under the ingress
// lock so it never runs inside pkt_receive on the other thread.
#define NET_TIMER_TICK_MS 10

static void* _net_timer_thread(void* arg){
    (void)arg;
    for(;;){
        usleep(NET_TIMER_TICK_MS * 1000);
        net_stack_lock();
        tcp_timer();
        net_stack_unlock();
        fflush(stdout);
    }
    return 0;
}

void net_start_timer_thread(void){
    pthread_attr_t attr;
    pthread_t      tid;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, _net_timer_thread, 0);
    pthread_attr_destroy(&attr);
}

// ---- test loss --------------------------------------------
//
// `run node <n> drop-tcp <skip> <count>`: of the TCP segments `node`
// sends from now on, let `skip` go, then drop the next `count` before
// they reach the wire (and before pcap sees them). The retransmission,
// fast retransmit, out-of-order and half-open tests need a lossy link;
// the simulator's UDP loopback never loses anything.
static Node* g_drop_node;
static int   g_drop_skip;
static int   g_drop_count;

void comm_drop_tcp(Node* node, int skip, int count){
    g_drop_node  = node;
    g_drop_skip  = skip;
    g_drop_count = count;
}

static bool comm_drop_this(char* pkt, size_t pkt_size, Interface* oif){
    if(!g_drop_node || g_drop_count <= 0 || oif->att_node != g_drop_node){
        return false;
    }
    const unsigned char* b = (const unsigned char*)pkt;
    size_t off = 12;
    if(pkt_size < off + 2) return false;
    if(b[off] == 0x81 && b[off + 1] == 0x00){
        off += 4;                       // 802.1Q tag
        if(pkt_size < off + 2) return false;
    }
    if(b[off] != 0x08 || b[off + 1] != 0x00) return false;
    off += 2;
    if(pkt_size < off + 20 || b[off + 9] != 6) return false;
    if(g_drop_skip > 0){
        g_drop_skip--;
        return false;
    }
    g_drop_count--;
    printf("Test loss : %s : TCP segment dropped on %s (%d more to drop)\n",
           oif->att_node->node_name, oif->if_name, g_drop_count);
    return true;
}
