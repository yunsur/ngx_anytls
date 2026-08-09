#ifndef NGX_ANYTLS_CLIENT_MUX_H_INCLUDED
#define NGX_ANYTLS_CLIENT_MUX_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;
struct ngx_anytls_stream_s;
typedef struct ngx_anytls_stream_s ngx_anytls_stream_t;


#include "ngx_anytls_mux_events.h"


/* Frame queuing — unified entry points for client output */
ngx_int_t ngx_anytls_client_mux_queue_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len);
ngx_int_t ngx_anytls_client_mux_queue_ref_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len);
ngx_int_t ngx_anytls_client_mux_queue_chain_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    ngx_chain_t *payload, size_t len, ngx_uint_t recycle_payload,
    ngx_uint_t room_checked);
ngx_int_t ngx_anytls_client_mux_send_synack(ngx_anytls_stream_t *st,
    u_char *data, size_t len);

/* Drain and backpressure */
ngx_int_t ngx_anytls_client_mux_drain(ngx_anytls_connection_t *ac,
    ngx_uint_t budget, ngx_anytls_drain_result_t *result);
void ngx_anytls_client_mux_post_write(ngx_anytls_connection_t *ac);
ngx_uint_t ngx_anytls_client_mux_has_room(ngx_anytls_connection_t *ac,
    size_t len);
void ngx_anytls_client_mux_on_writable(ngx_anytls_connection_t *ac);
void ngx_anytls_client_mux_resume_upstream_reads(ngx_anytls_connection_t *ac);
ngx_int_t ngx_anytls_client_mux_queue_error(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, u_char *data, size_t len);
void ngx_anytls_client_mux_mark_ready(ngx_anytls_stream_t *st);

/* Returns 1 if client output can accept at least payload_len bytes */
ngx_uint_t ngx_anytls_client_mux_can_accept_output(
    ngx_anytls_connection_t *ac, size_t payload_len);

#endif
