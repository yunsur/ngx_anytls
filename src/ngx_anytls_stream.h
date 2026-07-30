#ifndef NGX_ANYTLS_STREAM_H_INCLUDED
#define NGX_ANYTLS_STREAM_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_anytls_stream_t *ngx_anytls_stream_create(ngx_anytls_connection_t *ac,
    uint32_t id);
ngx_anytls_stream_t *ngx_anytls_stream_find(ngx_anytls_connection_t *ac,
    uint32_t id);
ngx_uint_t ngx_anytls_stream_exists(ngx_anytls_connection_t *ac, uint32_t id);
void ngx_anytls_stream_mark_closed_by_protocol(ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_stream_send_fin_and_close(ngx_anytls_stream_t *st);
void ngx_anytls_stream_close(ngx_anytls_stream_t *st);
void ngx_anytls_stream_remove_ready(ngx_anytls_stream_t *st);


ngx_pool_t *ngx_anytls_stream_pool(ngx_anytls_stream_t *st);


/* Stream operation enum — used by the dispatcher (client_handler)
 * and other protocol-adapter layers for stream lifecycle. */
typedef enum {
    NGX_ANYTLS_STREAM_OP_CREATE,
    NGX_ANYTLS_STREAM_OP_FIND,
    NGX_ANYTLS_STREAM_OP_EXISTS
} ngx_anytls_stream_op_e;

ngx_anytls_stream_t *ngx_anytls_stream_resolve(ngx_anytls_connection_t *ac,
    uint32_t id, ngx_anytls_stream_op_e op);


/* Stream state accessors — prefer over direct field access.
 * Used by the dispatcher and upstream mux for protocol-adjacent
 * stream state queries (first-PSH detection, payload acceptance). */
ngx_uint_t ngx_anytls_stream_is_first_psh(ngx_anytls_stream_t *st);
void ngx_anytls_stream_set_first_psh(ngx_anytls_stream_t *st,
    const ngx_anytls_addr_t *addr);
ngx_uint_t ngx_anytls_stream_can_accept_payload(ngx_anytls_stream_t *st);
ngx_uint_t ngx_anytls_stream_is_closed_by_protocol(ngx_anytls_stream_t *st);

#endif
