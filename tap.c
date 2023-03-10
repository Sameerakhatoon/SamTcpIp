#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "tap.h"

// Forward declarations.
int  tap_open(const char* ifname);
void tap_close(int fd);
long tap_send_raw(int fd, const void* buf, size_t len);
long tap_recv_raw(int fd, void* buf, size_t max);

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
