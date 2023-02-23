#include <arpa/inet.h>
#include <string.h>
#include "net.h"           // for UNSET_BIT
#include "utils.h"

// Forward declarations.
void apply_mask(char* prefix, char mask, char* str_prefix);
void layer2_fill_with_broadcast_mac(char* mac_array);

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
