#include <stddef.h>
#include "../utils.h"
#include "icmp.h"

// Forward declarations.
unsigned short icmp_checksum(const void* data, size_t len);

// ch12: thin wrapper. The actual RFC 1071 implementation moved to
// utils.c so IP (which now computes its own checksum) and any
// future L4 protocol with a checksum field share one tested
// implementation. The wrapper stays so ping.c and any other ICMP
// consumer can call by the more specific name.
unsigned short icmp_checksum(const void* data, size_t len){
    return inet_checksum(data, len);
}
