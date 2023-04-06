#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "pcap.h"

// Single global capture sink. Mutex protects all access.
static FILE*           g_cap        = NULL;
static pthread_mutex_t g_cap_mtx    = PTHREAD_MUTEX_INITIALIZER;

// libpcap global header (24 bytes). Standard layout.
#pragma pack(push, 1)
typedef struct PcapHdr {
    unsigned int   magic;            // 0xa1b2c3d4 = us-resolution timestamps
    unsigned short version_major;    // 2
    unsigned short version_minor;    // 4
    int            thiszone;         // 0 (UTC)
    unsigned int   sigfigs;          // 0
    unsigned int   snaplen;          // bytes per record cap
    unsigned int   network;          // LINKTYPE_ETHERNET=1
} PcapHdr;

typedef struct PcapRec {
    unsigned int   ts_sec;
    unsigned int   ts_usec;
    unsigned int   incl_len;
    unsigned int   orig_len;
} PcapRec;
#pragma pack(pop)

int pcap_open_file(const char* path){
    pthread_mutex_lock(&g_cap_mtx);
    if(g_cap){
        // Already open; replace silently.
        fclose(g_cap);
    }
    g_cap = fopen(path, "wb");
    if(!g_cap){
        pthread_mutex_unlock(&g_cap_mtx);
        printf("PCAP open failed : %s\n", path);
        return -1;
    }
    PcapHdr h = {0};
    h.magic         = 0xa1b2c3d4u;
    h.version_major = 2;
    h.version_minor = 4;
    h.thiszone      = 0;
    h.sigfigs       = 0;
    h.snaplen       = 65535;
    h.network       = 1;        // LINKTYPE_ETHERNET
    fwrite(&h, sizeof(h), 1, g_cap);
    fflush(g_cap);
    pthread_mutex_unlock(&g_cap_mtx);
    printf("PCAP open : %s\n", path);
    return 0;
}

void pcap_close_file(void){
    pthread_mutex_lock(&g_cap_mtx);
    if(g_cap){
        fclose(g_cap);
        g_cap = NULL;
        printf("PCAP close\n");
    }
    pthread_mutex_unlock(&g_cap_mtx);
}

void pcap_dump_frame(const void* buf, size_t len){
    pthread_mutex_lock(&g_cap_mtx);
    if(!g_cap){
        pthread_mutex_unlock(&g_cap_mtx);
        return;
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);

    PcapRec r;
    r.ts_sec   = (unsigned int)tv.tv_sec;
    r.ts_usec  = (unsigned int)tv.tv_usec;
    r.incl_len = (unsigned int)len;
    r.orig_len = (unsigned int)len;
    fwrite(&r,   sizeof(r), 1,   g_cap);
    fwrite(buf,  1,         len, g_cap);
    fflush(g_cap);
    pthread_mutex_unlock(&g_cap_mtx);
}
