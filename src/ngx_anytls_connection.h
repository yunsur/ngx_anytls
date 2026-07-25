#ifndef NGX_ANYTLS_CONNECTION_H_INCLUDED
#define NGX_ANYTLS_CONNECTION_H_INCLUDED

#include "ngx_stream_anytls_module.h"

void ngx_anytls_connection_init(ngx_stream_session_t *s,
    ngx_stream_anytls_srv_conf_t *conf);
ngx_int_t ngx_anytls_process_client_bytes(ngx_anytls_connection_t *ac,
    u_char *data, size_t len);
ngx_int_t ngx_anytls_handle_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_frame_t *frame);
void ngx_anytls_close_if_idle(ngx_anytls_connection_t *ac);

#endif
