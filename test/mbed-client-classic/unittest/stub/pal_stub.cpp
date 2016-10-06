#include "pal_stub.h"

palStatus_t pal_stub::status;

palStatus_t pal_init()
{
    return pal_stub::status;
}