#ifndef NGX_ANYTLS_MUX_EVENTS_H_INCLUDED
#define NGX_ANYTLS_MUX_EVENTS_H_INCLUDED

/* Shared types for client↔upstream mux backpressure coordination.
 * Both client_mux.h and upstream_mux.h include this header, avoiding
 * a directional dependency. */

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    size_t       pending_delta;
    ngx_uint_t   streams_resumed;
    unsigned     pressure_on:1;
    unsigned     pressure_released:1;
    unsigned     can_finalize:1;
} ngx_anytls_drain_result_t;

#endif
