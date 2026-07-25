#ifndef NGX_ANYTLS_UPSTREAM_H_INCLUDED
#define NGX_ANYTLS_UPSTREAM_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_int_t ngx_anytls_upstream_open(ngx_anytls_stream_t *st,
    ngx_anytls_addr_t *addr);
ngx_int_t ngx_anytls_upstream_open_resolved(ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_upstream_send_pending(ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_upstream_queue(ngx_anytls_stream_t *st, u_char *data,
    size_t len);

#endif
