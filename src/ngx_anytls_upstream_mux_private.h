#ifndef NGX_ANYTLS_UPSTREAM_MUX_PRIVATE_H_INCLUDED
#define NGX_ANYTLS_UPSTREAM_MUX_PRIVATE_H_INCLUDED

/* Upstream mux internal struct — included from connection_private.h
 * for backward compat; prefer direct include in upstream_mux.c only. */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

struct ngx_anytls_upstream_mux_s {
    ngx_queue_t              read_ready;
    ngx_queue_t              write_ready;
    ngx_queue_t              connect_pending;
};

#endif
