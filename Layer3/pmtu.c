#include <stdio.h>
#include <arpa/inet.h>
#include "pmtu.h"

// ch39: tiny linear cache. The realism we care about is that an
// entry CAN be installed (from ICMP receive or CLI) and the
// originate path CAN see it - not the lookup speed.
#define PMTU_CACHE_SIZE   16

typedef struct PmtuEntry {
    unsigned int dst_ip_host;   // 0 = empty slot
    unsigned int mtu;
} PmtuEntry;

static PmtuEntry g_pmtu_cache[PMTU_CACHE_SIZE];

static void ip_int_to_str(unsigned int ip_host_order, char* out16){
    unsigned int net = htonl(ip_host_order);
    inet_ntop(AF_INET, &net, out16, 16);
    out16[15] = '\0';
}

void pmtu_install(unsigned int dst_ip_host, unsigned int mtu){
    if(dst_ip_host == 0 || mtu == 0){
        return;
    }
    // Replace if dst already present (PMTUD can be re-triggered with
    // a smaller value if the path changes downward).
    int free_slot = -1;
    for(int i = 0; i < PMTU_CACHE_SIZE; i++){
        if(g_pmtu_cache[i].dst_ip_host == dst_ip_host){
            // RFC 1191: only adopt a SMALLER value (paths never
            // grow during a discovery). For the test rig we always
            // adopt - we want `pmtu set 80` then `pmtu set 60` to
            // both stick.
            g_pmtu_cache[i].mtu = mtu;
            char s[16];
            ip_int_to_str(dst_ip_host, s);
            printf("PMTU update : dst=%s mtu=%u\n", s, mtu);
            return;
        }
        if(g_pmtu_cache[i].dst_ip_host == 0 && free_slot < 0){
            free_slot = i;
        }
    }
    if(free_slot < 0){
        // Cache full. Drop the oldest (slot 0 today). Real impls
        // age. This is a 16-entry cache - the test rig won't hit it.
        free_slot = 0;
    }
    g_pmtu_cache[free_slot].dst_ip_host = dst_ip_host;
    g_pmtu_cache[free_slot].mtu         = mtu;
    char s[16];
    ip_int_to_str(dst_ip_host, s);
    printf("PMTU install : dst=%s mtu=%u\n", s, mtu);
}

unsigned int pmtu_lookup(unsigned int dst_ip_host){
    for(int i = 0; i < PMTU_CACHE_SIZE; i++){
        if(g_pmtu_cache[i].dst_ip_host == dst_ip_host){
            return g_pmtu_cache[i].mtu;
        }
    }
    return 0;
}

void pmtu_clear(unsigned int dst_ip_host){
    if(dst_ip_host == 0){
        for(int i = 0; i < PMTU_CACHE_SIZE; i++){
            g_pmtu_cache[i].dst_ip_host = 0;
            g_pmtu_cache[i].mtu         = 0;
        }
        printf("PMTU clear all\n");
        return;
    }
    for(int i = 0; i < PMTU_CACHE_SIZE; i++){
        if(g_pmtu_cache[i].dst_ip_host == dst_ip_host){
            g_pmtu_cache[i].dst_ip_host = 0;
            g_pmtu_cache[i].mtu         = 0;
            char s[16];
            ip_int_to_str(dst_ip_host, s);
            printf("PMTU clear : dst=%s\n", s);
            return;
        }
    }
}

void pmtu_dump(void){
    printf("PMTU cache:\n");
    int any = 0;
    for(int i = 0; i < PMTU_CACHE_SIZE; i++){
        if(g_pmtu_cache[i].dst_ip_host != 0){
            char s[16];
            ip_int_to_str(g_pmtu_cache[i].dst_ip_host, s);
            printf("  %-18s mtu=%u\n", s, g_pmtu_cache[i].mtu);
            any++;
        }
    }
    if(!any){
        printf("  (empty)\n");
    }
}
