#include "eventOS_scheduler.h"
#include "eventOS_event.h"
#include "eventOS_stub.h"

int8_t eventOS_stub::int8_value;

void eventOS_scheduler_mutex_wait(void){}

void eventOS_scheduler_mutex_release(void){}

int8_t eventOS_event_handler_create(void (*handler_func_ptr)(arm_event_s *), uint8_t init_event_type)
{
    return eventOS_stub::int8_value;
}

int8_t eventOS_event_send(arm_event_s *event)
{
    if(event->data_ptr && !eventOS_stub::int8_value)
    {
        free(event->data_ptr);
    }
    return eventOS_stub::int8_value;
}

