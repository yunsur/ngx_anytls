#include "ngx_anytls_upstream_resume.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int active;
    int ready;
    int posted;
} read_event_model_t;

static void
resume_read(read_event_model_t *event)
{
    ngx_anytls_upstream_resume_action_e action;

    action = ngx_anytls_upstream_resume_action(event->ready, event->posted);

    switch (action) {
    case NGX_ANYTLS_UPSTREAM_RESUME_NONE:
        assert(event->ready && event->posted);
        break;

    case NGX_ANYTLS_UPSTREAM_RESUME_ARM:
        assert(!event->ready);
        event->active = 1;
        break;

    case NGX_ANYTLS_UPSTREAM_RESUME_POST:
        assert(event->ready && !event->posted);
        event->posted = 1;
        break;
    }

    assert(!event->ready || event->active || event->posted);
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    read_event_model_t event = { 1, 0, 0 };
    uint8_t control;

    while (size != 0) {
        control = *data++;
        size--;

        switch (control & 3) {
        case 0:
            event.active = 0;
            if (control & 4) {
                event.ready = 1;
            }
            break;

        case 1:
            event.ready = 1;
            break;

        case 2:
            resume_read(&event);
            break;

        case 3:
            if (event.posted) {
                event.posted = 0;
                if (control & 4) {
                    event.ready = 1;
                    event.posted = 1;
                } else {
                    event.ready = 0;
                    event.active = 1;
                }
            }
            break;

        default:
            break;
        }
    }

    return 0;
}
