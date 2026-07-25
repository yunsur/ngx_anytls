#ifndef NGX_ANYTLS_UOT_H_INCLUDED
#define NGX_ANYTLS_UOT_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_int_t ngx_anytls_uot_open(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr);
ngx_int_t ngx_anytls_uot_resolved(ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_uot_client_payload(ngx_anytls_stream_t *st, u_char *data,
    size_t len);
void ngx_anytls_uot_close(ngx_anytls_stream_t *st);

#endif
