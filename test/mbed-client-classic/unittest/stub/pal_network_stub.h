#ifndef PAL_NETWORK_STUB_H
#define PAL_NETWORK_STUB_H

#include "pal_network.h"

namespace pal_network_stub
{
    extern palStatus_t status;
    extern palStatus_t new_status;
    extern uint32_t change_status_count; //status changed to new_status after this turns to 0

    extern palSocket_t socket;
    extern palSocketAddress_t socket_address;
    extern palIpV4Addr_t ipv4_address;
    extern palIpV6Addr_t ipv6_address;
    extern size_t size;
    extern uint32_t uint32_value;
    extern void *void_value;

}

#endif // PAL_NETWORK_STUB_H