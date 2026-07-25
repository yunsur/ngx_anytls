#ifndef NGX_ANYTLS_FALLBACK_H_INCLUDED
#define NGX_ANYTLS_FALLBACK_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_int_t ngx_anytls_fallback_start(ngx_anytls_connection_t *ac, u_char *raw,
    size_t raw_len);

#endif
