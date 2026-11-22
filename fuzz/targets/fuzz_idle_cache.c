#include "ngx_anytls_idle_cache.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum {
    MODEL_OPEN = 0,
    MODEL_ARMED,
    MODEL_CLOSED
} model_state_e;

static ngx_anytls_idle_cache_action_e
model_step(model_state_e *state, ngx_anytls_idle_cache_event_e event,
    int eligible)
{
    if (*state == MODEL_CLOSED) {
        return NGX_ANYTLS_IDLE_CACHE_NONE;
    }

    if (event == NGX_ANYTLS_IDLE_CACHE_CHECK) {
        if (*state == MODEL_OPEN && eligible) {
            *state = MODEL_ARMED;
            return NGX_ANYTLS_IDLE_CACHE_ARM;
        }
        return NGX_ANYTLS_IDLE_CACHE_NONE;
    }

    if (event == NGX_ANYTLS_IDLE_CACHE_ACTIVITY) {
        if (*state == MODEL_ARMED) {
            *state = MODEL_OPEN;
            return NGX_ANYTLS_IDLE_CACHE_CANCEL;
        }
        return NGX_ANYTLS_IDLE_CACHE_NONE;
    }

    if (event == NGX_ANYTLS_IDLE_CACHE_TIMER) {
        if (*state == MODEL_ARMED) {
            *state = MODEL_OPEN;
            return eligible ? NGX_ANYTLS_IDLE_CACHE_TRIM
                            : NGX_ANYTLS_IDLE_CACHE_NONE;
        }
        return NGX_ANYTLS_IDLE_CACHE_NONE;
    }

    if (*state == MODEL_ARMED) {
        *state = MODEL_CLOSED;
        return NGX_ANYTLS_IDLE_CACHE_CANCEL;
    }
    *state = MODEL_CLOSED;
    return NGX_ANYTLS_IDLE_CACHE_NONE;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_anytls_idle_cache_policy_t policy = { 0 };
    model_state_e model_state = MODEL_OPEN;
    ngx_anytls_idle_cache_event_e event;
    ngx_anytls_idle_cache_action_e actual, expected;
    size_t active_streams, pending_input, pending_output, frames;
    uint8_t control;
    int closing, eligible, expected_eligible;

    while (size != 0) {
        control = *data++;
        size--;

        event = (ngx_anytls_idle_cache_event_e) (control & 3);
        active_streams = (control >> 2) & 1;
        pending_input = (control >> 3) & 1;
        pending_output = (control >> 4) & 1;
        frames = (control >> 5) & 1;
        closing = (control >> 6) & 1;
        expected_eligible = !closing && active_streams == 0
                            && pending_input == 0 && pending_output == 0
                            && frames == 0;
        eligible = ngx_anytls_idle_cache_eligible(
            active_streams, pending_input, pending_output, frames, closing);
        if (eligible != expected_eligible) {
            abort();
        }

        expected = model_step(&model_state, event, eligible);
        actual = ngx_anytls_idle_cache_transition(&policy, event, eligible);
        if (actual != expected || (int) policy.state != (int) model_state) {
            abort();
        }

        if (actual == NGX_ANYTLS_IDLE_CACHE_TRIM
            && (event != NGX_ANYTLS_IDLE_CACHE_TIMER || !eligible))
        {
            abort();
        }
    }

    return 0;
}
