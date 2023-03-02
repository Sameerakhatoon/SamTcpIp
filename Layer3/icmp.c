#include <stddef.h>
#include "icmp.h"

// Forward declarations.
unsigned short icmp_checksum(const void* data, size_t len);

// RFC 1071 Internet Checksum.
//
// Algorithm:
//   1. Treat the buffer as a sequence of 16-bit words. Sum them
//      with carry-out folded back into the low 16 bits.
//   2. If the buffer has an odd length, the final byte is treated
//      as the high byte of a 16-bit word with low byte zero.
//   3. After the loop, keep folding carry until the high half is
//      zero.
//   4. Return the ones-complement of the result.
//
// Self-consistency: at the receiver, run the same algorithm over
// the WHOLE received buffer (including the stored checksum field).
// A valid message yields 0.
unsigned short icmp_checksum(const void* data, size_t len){
    const unsigned char* p = (const unsigned char*)data;
    unsigned int sum = 0;

    // Sum 16-bit words.
    while(len > 1){
        unsigned int word = ((unsigned int)p[0] << 8) | (unsigned int)p[1];
        sum += word;
        p   += 2;
        len -= 2;
    }
    // Odd trailing byte.
    if(len == 1){
        sum += ((unsigned int)p[0] << 8);
    }
    // Fold carry-out.
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum & 0xFFFF);
}
