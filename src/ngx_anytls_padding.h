#ifndef NGX_ANYTLS_PADDING_H_INCLUDED
#define NGX_ANYTLS_PADDING_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_int_t ngx_anytls_padding_validate(u_char *data, size_t len);
char *ngx_anytls_padding_load(ngx_conf_t *cf,
    ngx_stream_anytls_srv_conf_t *conf);

#endif
