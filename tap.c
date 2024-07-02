#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include "comm.h"
#include "graph.h"
#include "tap.h"

// Forward declarations.
int   tap_open(const char* ifname);
void  tap_close(int fd);
long  tap_send_raw(int fd, const void* buf, size_t len);
long  tap_recv_raw(int fd, void* buf, size_t max);
int   tap_attach(Node* node, const char* ifname, const char* iif_name);
void  tap_detach(void);
bool  tap_is_attached_iif(Interface* iif);
long  tap_write_frame(const void* buf, size_t len);
int   tap_ifup(const char* ifname);
int   tap_set_host_ip(const char* ifname, const char* ip, int mask_bits);
static void* tap_recv_thread(void* arg);
static int   open_ioctl_socket(void);

int tap_open(const char* ifname){
    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0){
        printf("TAP open failed : /dev/net/tun : %s (errno=%d)\n",
               strerror(errno), errno);
        return -1;
    }

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    // IFF_TAP gives us ethernet frames (vs IFF_TUN's L3 packets).
    // IFF_NO_PI suppresses the 4-byte "packet info" prefix the
    // kernel would otherwise prepend; with this flag what we read
    // is exactly the wire ethernet frame.
    req.ifr_flags = IFF_TAP | IFF_NO_PI;
    if(ifname && *ifname){
        strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);
        req.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if(ioctl(fd, TUNSETIFF, &req) < 0){
        int saved = errno;
        // The single failure mode the test harness checks for is
        // EPERM under non-root - "Operation not permitted". Print
        // it verbatim plus errno so the assertion can grep either.
        printf("TAP ioctl TUNSETIFF failed : %s (errno=%d)\n",
               strerror(saved), saved);
        close(fd);
        errno = saved;
        return -1;
    }

    printf("TAP opened : ifname=%s fd=%d\n", req.ifr_name, fd);
    return fd;
}

void tap_close(int fd){
    if(fd >= 0){
        close(fd);
    }
}

long tap_send_raw(int fd, const void* buf, size_t len){
    if(fd < 0){
        return -1;
    }
    ssize_t n = write(fd, buf, len);
    if(n < 0){
        printf("TAP send failed : %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    return (long)n;
}

long tap_recv_raw(int fd, void* buf, size_t max){
    if(fd < 0){
        return -1;
    }
    ssize_t n = read(fd, buf, max);
    if(n < 0){
        printf("TAP recv failed : %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    return (long)n;
}

// ---- ch15: attach / detach + recv thread --------------------------------

// Single-instance state. The userspace stack
// is one Node; one TAP is enough.
static int              g_tap_fd     = -1;
static Node*            g_tap_node   = NULL;
static Interface*       g_tap_iif    = NULL;
static pthread_t        g_tap_thread_id;
static atomic_int       g_tap_stop   = 0;
static atomic_int       g_tap_running = 0;

static void* tap_recv_thread(void* arg){
    (void)arg;
    unsigned char buf[2048];
    printf("TAP recv thread started\n");
    while(!atomic_load(&g_tap_stop)){
        // 100ms select gate so detach can interrupt without
        // blocking forever on read().
        fd_set rfds;
        struct timeval tv = {0, 100 * 1000};
        FD_ZERO(&rfds);
        FD_SET(g_tap_fd, &rfds);
        int rc = select(g_tap_fd + 1, &rfds, 0, 0, &tv);
        if(rc < 0){
            if(errno == EINTR) continue;
            printf("TAP recv : select error : %s (errno=%d)\n",
                   strerror(errno), errno);
            break;
        }
        if(rc == 0) continue;     // timeout - loop back, check stop

        long n = tap_recv_raw(g_tap_fd, buf, sizeof(buf));
        if(n <= 0) continue;
        printf("TAP recv : %ld bytes on %s/%s\n",
               n, g_tap_node->node_name, g_tap_iif->if_name);
        // Hand to the existing L2 ingress. The TAP gives raw
        // ethernet frames (IFF_NO_PI strips the kernel prefix),
        // exactly what pkt_receive expects.
        pkt_receive(g_tap_node, g_tap_iif, (char*)buf, (size_t)n);
    }
    atomic_store(&g_tap_running, 0);
    printf("TAP recv thread exited\n");
    return NULL;
}

int tap_attach(Node* node, const char* ifname, const char* iif_name){
    if(g_tap_fd >= 0){
        printf("TAP attach failed : already attached\n");
        return -1;
    }
    if(!node || !ifname || !iif_name){
        printf("TAP attach failed : bad args\n");
        return -1;
    }
    Interface* iif = get_node_if_by_name(node, (char*)iif_name);
    if(!iif){
        printf("TAP attach failed : no such interface `%s` on node %s\n",
               iif_name, node->node_name);
        return -1;
    }
    int fd = tap_open(ifname);
    if(fd < 0){
        // tap_open already printed the diagnostic.
        return -1;
    }
    g_tap_fd       = fd;
    g_tap_node     = node;
    g_tap_iif      = iif;
    // The TAP is a real Ethernet link: full 1500-byte MTU, so we
    // only fragment what a real stack would.
    IF_MTU(iif)    = ETH_DEFAULT_MTU;
    atomic_store(&g_tap_stop, 0);
    atomic_store(&g_tap_running, 1);

    if(pthread_create(&g_tap_thread_id, NULL, tap_recv_thread, NULL) != 0){
        printf("TAP attach failed : pthread_create errno=%d\n", errno);
        tap_close(g_tap_fd);
        g_tap_fd   = -1;
        g_tap_node = NULL;
        g_tap_iif  = NULL;
        atomic_store(&g_tap_running, 0);
        return -1;
    }
    printf("TAP attach : %s -> %s/%s fd=%d\n",
           ifname, node->node_name, iif_name, fd);
    return 0;
}

// ch16: send-side integration.
//
// Both helpers tolerate "no TAP attached" by returning the
// safe default - callers don't need to guard. This keeps the
// integration point in comm.c::send_pkt_out small.

bool tap_is_attached_iif(Interface* iif){
    return iif != NULL && g_tap_iif == iif;
}

long tap_write_frame(const void* buf, size_t len){
    if(g_tap_fd < 0){
        return -1;
    }
    long n = tap_send_raw(g_tap_fd, buf, len);
    if(n > 0){
        printf("TAP send : %ld bytes via %s/%s\n",
               n, g_tap_node->node_name, g_tap_iif->if_name);
    }
    return n;
}

void tap_detach(void){
    if(g_tap_fd < 0){
        return;
    }
    atomic_store(&g_tap_stop, 1);
    pthread_join(g_tap_thread_id, NULL);
    tap_close(g_tap_fd);
    if(g_tap_iif){
        IF_MTU(g_tap_iif) = SIM_INTF_DEFAULT_MTU;   // back on the simulator wire
    }
    g_tap_fd   = -1;
    g_tap_node = NULL;
    g_tap_iif  = NULL;
    printf("TAP detach\n");
}

// ---- ch18: kernel-side interface bring-up + IP assignment --------------

// Helper: open a dummy AF_INET DGRAM socket. The ioctls
// (SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFNETMASK) operate on the
// kernel's interface table via ANY socket, not specifically the
// TAP fd. Closing the dummy socket is fine; the ioctls have
// already taken effect kernel-side.
static int open_ioctl_socket(void){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0){
        printf("TAP ifctl : socket() failed : %s (errno=%d)\n",
               strerror(errno), errno);
        return -1;
    }
    return s;
}

int tap_ifup(const char* ifname){
    if(!ifname || !*ifname){
        printf("TAP ifup : bad ifname\n");
        return -1;
    }
    int s = open_ioctl_socket();
    if(s < 0) return -1;

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);
    req.ifr_name[IFNAMSIZ - 1] = '\0';

    // Read flags first so we don't clobber unrelated bits.
    if(ioctl(s, SIOCGIFFLAGS, &req) < 0){
        printf("TAP ifup : SIOCGIFFLAGS failed : %s (errno=%d)\n",
               strerror(errno), errno);
        close(s);
        return -1;
    }
    req.ifr_flags |= IFF_UP | IFF_RUNNING;
    if(ioctl(s, SIOCSIFFLAGS, &req) < 0){
        printf("TAP ifup : SIOCSIFFLAGS failed : %s (errno=%d)\n",
               strerror(errno), errno);
        close(s);
        return -1;
    }
    close(s);
    printf("TAP ifup : %s is UP\n", ifname);
    return 0;
}

int tap_set_host_ip(const char* ifname, const char* ip, int mask_bits){
    if(!ifname || !*ifname || !ip || mask_bits < 0 || mask_bits > 32){
        printf("TAP host-ip : bad args\n");
        return -1;
    }
    unsigned int ip_net = 0;
    if(inet_pton(AF_INET, ip, &ip_net) != 1){
        printf("TAP host-ip : bad ip `%s`\n", ip);
        return -1;
    }
    int s = open_ioctl_socket();
    if(s < 0) return -1;

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);
    req.ifr_name[IFNAMSIZ - 1] = '\0';

    // SIOCSIFADDR expects a sockaddr_in inside ifr_addr.
    struct sockaddr_in* sin = (struct sockaddr_in*)&req.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip_net;
    if(ioctl(s, SIOCSIFADDR, &req) < 0){
        printf("TAP host-ip : SIOCSIFADDR failed : %s (errno=%d)\n",
               strerror(errno), errno);
        close(s);
        return -1;
    }

    // Compute the netmask as a contiguous high-bits-set value.
    unsigned int mask_host = (mask_bits == 0) ? 0
                          : (mask_bits == 32) ? 0xFFFFFFFFu
                          : (0xFFFFFFFFu << (32 - mask_bits));
    sin->sin_addr.s_addr = htonl(mask_host);
    if(ioctl(s, SIOCSIFNETMASK, &req) < 0){
        printf("TAP host-ip : SIOCSIFNETMASK failed : %s (errno=%d)\n",
               strerror(errno), errno);
        close(s);
        return -1;
    }
    close(s);
    printf("TAP host-ip : %s set to %s/%d\n", ifname, ip, mask_bits);
    return 0;
}
