#ifndef NGX_ANYTLS_STREAM_H_INCLUDED
#define NGX_ANYTLS_STREAM_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_anytls_stream_t *ngx_anytls_stream_create(ngx_anytls_connection_t *ac,
    uint32_t id);
ngx_anytls_stream_t *ngx_anytls_stream_find(ngx_anytls_connection_t *ac,
    uint32_t id);
void ngx_anytls_stream_close(ngx_anytls_stream_t *st);
void ngx_anytls_stream_mark_ready(ngx_anytls_stream_t *st);
void ngx_anytls_stream_remove_ready(ngx_anytls_stream_t *st);

#endif
