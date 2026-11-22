#ifndef NGX_ANYTLS_IDLE_CACHE_H_INCLUDED
#define NGX_ANYTLS_IDLE_CACHE_H_INCLUDED

#include <stddef.h>

#define NGX_ANYTLS_IDLE_CACHE_TRIM_DELAY  1000U

typedef enum {
    NGX_ANYTLS_IDLE_CACHE_OPEN = 0,
    NGX_ANYTLS_IDLE_CACHE_ARMED,
    NGX_ANYTLS_IDLE_CACHE_CLOSED
} ngx_anytls_idle_cache_state_e;

typedef enum {
    NGX_ANYTLS_IDLE_CACHE_CHECK = 0,
    NGX_ANYTLS_IDLE_CACHE_ACTIVITY,
    NGX_ANYTLS_IDLE_CACHE_TIMER,
    NGX_ANYTLS_IDLE_CACHE_FINALIZE
} ngx_anytls_idle_cache_event_e;

typedef enum {
    NGX_ANYTLS_IDLE_CACHE_NONE = 0,
    NGX_ANYTLS_IDLE_CACHE_ARM,
    NGX_ANYTLS_IDLE_CACHE_CANCEL,
    NGX_ANYTLS_IDLE_CACHE_TRIM
} ngx_anytls_idle_cache_action_e;

typedef struct {
    ngx_anytls_idle_cache_state_e  state;
} ngx_anytls_idle_cache_policy_t;

static inline int
ngx_anytls_idle_cache_eligible(size_t active_streams, size_t pending_input,
    size_t pending_output, size_t frames, int closing)
{
    return !closing && active_streams == 0 && pending_input == 0
           && pending_output == 0 && frames == 0;
}


static inline ngx_anytls_idle_cache_action_e
ngx_anytls_idle_cache_transition(ngx_anytls_idle_cache_policy_t *policy,
    ngx_anytls_idle_cache_event_e event, int eligible)
{
    if (policy->state == NGX_ANYTLS_IDLE_CACHE_CLOSED) {
        return NGX_ANYTLS_IDLE_CACHE_NONE;
    }

    switch (event) {
    case NGX_ANYTLS_IDLE_CACHE_CHECK:
        if (policy->state == NGX_ANYTLS_IDLE_CACHE_OPEN && eligible) {
            policy->state = NGX_ANYTLS_IDLE_CACHE_ARMED;
            return NGX_ANYTLS_IDLE_CACHE_ARM;
        }
        break;

    case NGX_ANYTLS_IDLE_CACHE_ACTIVITY:
        if (policy->state == NGX_ANYTLS_IDLE_CACHE_ARMED) {
            policy->state = NGX_ANYTLS_IDLE_CACHE_OPEN;
            return NGX_ANYTLS_IDLE_CACHE_CANCEL;
        }
        break;

    case NGX_ANYTLS_IDLE_CACHE_TIMER:
        if (policy->state == NGX_ANYTLS_IDLE_CACHE_ARMED) {
            policy->state = NGX_ANYTLS_IDLE_CACHE_OPEN;
            return eligible ? NGX_ANYTLS_IDLE_CACHE_TRIM
                            : NGX_ANYTLS_IDLE_CACHE_NONE;
        }
        break;

    case NGX_ANYTLS_IDLE_CACHE_FINALIZE:
        if (policy->state == NGX_ANYTLS_IDLE_CACHE_ARMED) {
            policy->state = NGX_ANYTLS_IDLE_CACHE_CLOSED;
            return NGX_ANYTLS_IDLE_CACHE_CANCEL;
        }
        policy->state = NGX_ANYTLS_IDLE_CACHE_CLOSED;
        break;
    }

    return NGX_ANYTLS_IDLE_CACHE_NONE;
}


static inline ngx_anytls_idle_cache_action_e
ngx_anytls_idle_cache_recheck(ngx_anytls_idle_cache_policy_t *policy,
    size_t active_streams, size_t pending_input, size_t pending_output,
    size_t frames, int closing)
{
    return ngx_anytls_idle_cache_transition(
        policy, NGX_ANYTLS_IDLE_CACHE_CHECK,
        ngx_anytls_idle_cache_eligible(
            active_streams, pending_input, pending_output, frames, closing));
}

#endif /* NGX_ANYTLS_IDLE_CACHE_H_INCLUDED */
