#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include "net.h"           // for UNSET_BIT
#include "utils.h"

// Forward declarations.
void apply_mask(char* prefix, char mask, char* str_prefix);
void layer2_fill_with_broadcast_mac(char* mac_array);
unsigned short inet_checksum(const void* data, size_t len);

// Round an IP down to its network address. Convert to host-order
// uint, clear the low (32 - mask) bits, convert back.
void apply_mask(char* prefix, char mask, char* str_prefix){
    unsigned int binary_prefix = 0;
    inet_pton(AF_INET, prefix, &binary_prefix);
    binary_prefix = htonl(binary_prefix);
    for(int i = 0; i < (32 - mask); i++){
        UNSET_BIT(binary_prefix, i);
    }
    binary_prefix = htonl(binary_prefix);
    inet_ntop(AF_INET, &binary_prefix, str_prefix, 16);
    str_prefix[15] = '\0';
}

void layer2_fill_with_broadcast_mac(char* mac_array){
    mac_array[0] = (char)0xFF;
    mac_array[1] = (char)0xFF;
    mac_array[2] = (char)0xFF;
    mac_array[3] = (char)0xFF;
    mac_array[4] = (char)0xFF;
    mac_array[5] = (char)0xFF;
}

// RFC 1071 Internet Checksum (ch12). See utils.h for the contract.
//
// Algorithm:
//   1. Read the buffer as 16-bit big-endian words. Sum with
//      carry-out folded back into the low 16 bits.
//   2. If the buffer has an odd length, the final byte is treated
//      as the high byte of a 16-bit word with low byte zero.
//   3. After the loop, keep folding carry until the high half is
//      zero.
//   4. Return the ones-complement of the result.
//
// Big-endian byte read makes the result byte-stable across host
// architectures - real on-wire bytes always produce the same
// checksum.
unsigned short inet_checksum(const void* data, size_t len){
    const unsigned char* p = (const unsigned char*)data;
    unsigned int sum = 0;

    while(len > 1){
        unsigned int word = ((unsigned int)p[0] << 8) | (unsigned int)p[1];
        sum += word;
        p   += 2;
        len -= 2;
    }
    if(len == 1){
        sum += ((unsigned int)p[0] << 8);
    }
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum & 0xFFFF);
}

unsigned long net_now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)ts.tv_sec * 1000ul + (unsigned long)(ts.tv_nsec / 1000000);
}
