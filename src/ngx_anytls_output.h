#ifndef NGX_ANYTLS_OUTPUT_H_INCLUDED
#define NGX_ANYTLS_OUTPUT_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_int_t ngx_anytls_queue_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len);
ngx_int_t ngx_anytls_queue_chain_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    ngx_chain_t *payload, size_t len, ngx_uint_t recycle_payload);
ngx_int_t ngx_anytls_flush(ngx_anytls_connection_t *ac);
void ngx_anytls_post_write(ngx_anytls_connection_t *ac);
ngx_uint_t ngx_anytls_output_has_room(ngx_anytls_connection_t *ac, size_t len);

#endif
