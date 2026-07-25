#ifndef NGX_ANYTLS_RESOLVER_H_INCLUDED
#define NGX_ANYTLS_RESOLVER_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_int_t ngx_anytls_resolve_addr(ngx_anytls_stream_t *st,
    ngx_anytls_resolve_target_e target, ngx_anytls_addr_t *addr);
void ngx_anytls_resolver_cancel(ngx_anytls_stream_t *st);

#endif
