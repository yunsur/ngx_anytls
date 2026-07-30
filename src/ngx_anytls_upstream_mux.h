#ifndef NGX_ANYTLS_UPSTREAM_MUX_H_INCLUDED
#define NGX_ANYTLS_UPSTREAM_MUX_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_anytls_socksaddr.h"
#include "ngx_anytls_mux_events.h"

#define NGX_ANYTLS_SCHEDULE_FRAME_BUDGET   32
#define NGX_ANYTLS_SCHEDULE_BYTE_BUDGET    ((size_t) -1)
#define NGX_ANYTLS_SCHEDULE_STREAM_BUDGET  16

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;
struct ngx_anytls_stream_s;
typedef struct ngx_anytls_stream_s ngx_anytls_stream_t;


/* Upstream stream status — single query replaces multiple predicates */
typedef struct {
    unsigned is_packet_mode:1;    /* replaces is_uot() */
    unsigned read_blocked:1;      /* replaces read_blocked() */
    unsigned can_accept:1;        /* stream can accept more client data */
    unsigned is_closing:1;
} ngx_anytls_upstream_mux_status_t;


/* init / destroy */
ngx_int_t ngx_anytls_upstream_mux_init(ngx_anytls_connection_t *ac);
void ngx_anytls_upstream_mux_destroy(ngx_anytls_connection_t *ac);

/* stream lifecycle — called by client_handler dispatcher */
ngx_int_t ngx_anytls_upstream_mux_open(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr);
ngx_int_t ngx_anytls_upstream_mux_handle_client_payload(
    ngx_anytls_stream_t *st, u_char *data, size_t len);

void ngx_anytls_upstream_mux_suspend_reads(ngx_anytls_connection_t *ac);
void ngx_anytls_upstream_mux_handle_client_fin(
    ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_upstream_mux_handle_first_psh(
    ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st,
    ngx_anytls_addr_t *addr, u_char *payload, size_t payload_len);
ngx_int_t ngx_anytls_upstream_mux_open_resolved(ngx_anytls_stream_t *st);

/* events from nginx adapters — called by upstream.c and uot.c */
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
void ngx_anytls_upstream_mux_stream_closing(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st);

/* backpressure from client_mux */
void ngx_anytls_upstream_mux_on_client_mux_result(
    ngx_anytls_connection_t *ac,
    const ngx_anytls_drain_result_t *result);



/* --- Unified upstream event dispatch --- */

typedef enum {
    NGX_ANYTLS_UPSTREAM_EVENT_RESOLVE_OK = 0,
    NGX_ANYTLS_UPSTREAM_EVENT_RESOLVE_ERROR,
} ngx_anytls_upstream_event_type_e;

typedef struct {
    ngx_anytls_upstream_event_type_e type;
    ngx_anytls_stream_t             *st;
    uint32_t                         stream_id;
    ngx_addr_t                      *sockaddr;
    ngx_int_t                        status;
} ngx_anytls_upstream_event_t;

void ngx_anytls_upstream_mux_event(ngx_anytls_connection_t *ac,
    ngx_anytls_upstream_event_t *event);

/* upstream stream status (replaces is_uot, read_blocked, should_arm_read) */
ngx_anytls_upstream_mux_status_t ngx_anytls_upstream_mux_stream_status(
    ngx_anytls_stream_t *st);

/* block upstream reads — used by nginx event handlers for backpressure.
 * Inserts into the mux blocked-reads queue so process_blocked can resume. */
ngx_int_t ngx_anytls_upstream_mux_block_read(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_event_t *rev);

#endif
