#ifndef NGX_ANYTLS_OUTPUT_H_INCLUDED
#define NGX_ANYTLS_OUTPUT_H_INCLUDED

#include "ngx_stream_anytls_module.h"

typedef struct {
    size_t       pending_delta;
    unsigned     pressure_on:1;
    unsigned     can_finalize:1;
} ngx_anytls_drain_result_t;

ngx_int_t ngx_anytls_queue_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len);
ngx_int_t ngx_anytls_queue_ref_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len);
ngx_int_t ngx_anytls_queue_chain_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    ngx_chain_t *payload, size_t len, ngx_uint_t recycle_payload);
ngx_int_t ngx_anytls_send_synack(ngx_anytls_stream_t *st, u_char *data,
    size_t len);
ngx_int_t ngx_anytls_flush(ngx_anytls_connection_t *ac, ngx_uint_t budget);
void ngx_anytls_post_write(ngx_anytls_connection_t *ac);
ngx_uint_t ngx_anytls_output_has_room(ngx_anytls_connection_t *ac, size_t len);

ngx_int_t ngx_anytls_mux_queue_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len);
ngx_int_t ngx_anytls_mux_drain_client(ngx_anytls_connection_t *ac,
    ngx_uint_t budget, ngx_anytls_drain_result_t *result);
void ngx_anytls_mux_on_client_writable(ngx_anytls_connection_t *ac);
void ngx_anytls_resume_upstream_reads(ngx_anytls_connection_t *ac);
ngx_int_t ngx_anytls_client_mux_queue_error(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, u_char *data, size_t len);

#endif
