#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "comm.h"
#include "graph.h"
#include "tap.h"

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

// Static scratch buffers used by the (single) receiver thread and
// by the sender. Sender shares: only valid while no other call to
// send_pkt_out is in flight, which is fine for our single-threaded
// CLI driver.
static char recv_buffer[MAX_PACKET_BUFFER_SIZE];
static char send_buffer[MAX_PACKET_BUFFER_SIZE];

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

int pkt_receive(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    layer2_frame_recv(node, iif, pkt, pkt_size);
    return 0;
}
