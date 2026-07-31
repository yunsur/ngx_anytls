#ifndef NGX_ANYTLS_UPSTREAM_STATE_H_INCLUDED
#define NGX_ANYTLS_UPSTREAM_STATE_H_INCLUDED

#include "ngx_stream_anytls_module.h"

ngx_int_t ngx_anytls_upstream_state_open(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker, const ngx_str_t *peer);
void ngx_anytls_upstream_state_on_connect(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker);
void ngx_anytls_upstream_state_on_first_byte(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker);
void ngx_anytls_upstream_state_add_bytes_sent(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker, off_t bytes);
void ngx_anytls_upstream_state_add_bytes_received(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker, off_t bytes);
void ngx_anytls_upstream_state_finalize(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker);

#endif
