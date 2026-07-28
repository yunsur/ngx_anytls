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
void ngx_anytls_stream_mark_ready(ngx_anytls_stream_t *st);
void ngx_anytls_stream_remove_ready(ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_mux_mark_closing(ngx_anytls_stream_t *st);


static ngx_inline ngx_pool_t *
ngx_anytls_stream_pool(ngx_anytls_stream_t *st)
{
    if (st->pool == NULL) {
        st->pool = ngx_create_pool(NGX_ANYTLS_STREAM_POOL_SIZE, st->ac->log);
    }
    return st->pool;
}

#endif
