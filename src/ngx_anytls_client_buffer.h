#ifndef NGX_ANYTLS_CLIENT_BUFFER_H_INCLUDED
#define NGX_ANYTLS_CLIENT_BUFFER_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_anytls_protocol.h"

#define NGX_ANYTLS_CLIENT_BUFFER_INITIAL_SIZE  4096
#define NGX_ANYTLS_CLIENT_BUFFER_MAX_SIZE      \
    (NGX_ANYTLS_FRAME_HEADER_LEN + NGX_ANYTLS_MAX_FRAME_DATA)

typedef struct {
    u_char  *data;
    size_t   capacity;
    size_t   remnant_len;
} ngx_anytls_client_buffer_t;

ngx_int_t ngx_anytls_client_buffer_init(
    ngx_anytls_client_buffer_t *buffer, ngx_log_t *log);
ngx_int_t ngx_anytls_client_buffer_prepare(
    ngx_anytls_client_buffer_t *buffer, ngx_uint_t authenticated,
    ngx_log_t *log);
void ngx_anytls_client_buffer_release_oversized(
    ngx_anytls_client_buffer_t *buffer);
void ngx_anytls_client_buffer_destroy(ngx_anytls_client_buffer_t *buffer);

#endif
