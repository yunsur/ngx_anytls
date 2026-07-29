#ifndef NGX_ANYTLS_UPSTREAM_MUX_H_INCLUDED
#define NGX_ANYTLS_UPSTREAM_MUX_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_anytls_socksaddr.h"

#define NGX_ANYTLS_SCHEDULE_FRAME_BUDGET   32
#define NGX_ANYTLS_SCHEDULE_BYTE_BUDGET    ((size_t) -1)
#define NGX_ANYTLS_SCHEDULE_STREAM_BUDGET  16

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;
struct ngx_anytls_stream_s;
typedef struct ngx_anytls_stream_s ngx_anytls_stream_t;


ngx_int_t ngx_anytls_upstream_mux_init(ngx_anytls_connection_t *ac);
void ngx_anytls_upstream_mux_destroy(ngx_anytls_connection_t *ac);
void ngx_anytls_upstream_mux_suspend_reads(ngx_anytls_connection_t *ac);
void ngx_anytls_upstream_mux_resume_reads(ngx_anytls_connection_t *ac);
ngx_int_t ngx_anytls_upstream_mux_open(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr);
ngx_int_t ngx_anytls_upstream_mux_open_resolved(
    ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_upstream_mux_on_connect_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_on_read_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_on_write_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_on_connect_pending(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_cancel_connect(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_resume_upstream_reads(ngx_anytls_connection_t *ac);
ngx_int_t ngx_anytls_upstream_mux_on_read_blocked(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_event_t *rev);
void ngx_anytls_upstream_mux_stream_closing(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_unblock_read(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);
ngx_uint_t ngx_anytls_upstream_mux_is_uot(ngx_anytls_stream_t *st);
ngx_uint_t ngx_anytls_upstream_mux_should_arm_read(
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_arm_read_if_needed(
    ngx_anytls_stream_t *st);
ngx_uint_t ngx_anytls_upstream_mux_read_blocked(
    ngx_anytls_stream_t *st);
void ngx_anytls_upstream_mux_handle_client_fin(
    ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_upstream_mux_handle_client_payload(
    ngx_anytls_stream_t *st, u_char *data, size_t len);
ngx_int_t ngx_anytls_upstream_mux_handle_first_psh(
    ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st,
    ngx_anytls_addr_t *addr, u_char *payload, size_t payload_len);


#endif
