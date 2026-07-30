#ifndef NGX_ANYTLS_STREAM_PRIVATE_H_INCLUDED
#define NGX_ANYTLS_STREAM_PRIVATE_H_INCLUDED

/* Stream struct layout — private to modules that need direct field access.
 * Included from connection_private.h for backward compat;
 * prefer including directly only when you genuinely need stream internals. */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event_connect.h>

#include "ngx_stream_anytls_module.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"
#include "ngx_anytls_upstream_state.h"
#include "ngx_anytls_client_mux.h"

struct ngx_anytls_stream_s {
    uint32_t                 id;
    ngx_anytls_stream_state_e state;
    ngx_anytls_connection_t *ac;
    ngx_anytls_upstream_type_e upstream_type;
    ngx_anytls_addr_t        target;
    ngx_pool_t              *pool;

    ngx_queue_t              ready_queue;
    ngx_queue_t              link;
    ngx_queue_t              upstream_block;
    ngx_queue_t              upstream_read_queue;
    ngx_queue_t              upstream_write_queue;
    ngx_queue_t              connect_queue;
    ngx_queue_t              closing_queue;

    ngx_peer_connection_t    peer;
    ngx_connection_t        *upstream;
    ngx_str_t                upstream_name;
    ngx_anytls_upstream_state_tracker_t upstream_state;
    ngx_anytls_pending_t    *pending_in;
    ngx_anytls_pending_t   **pending_in_last;
    ngx_anytls_pending_t    *free_pending_in;
    size_t                   pending_in_bytes;

    ngx_anytls_out_frame_t  *out;
    ngx_anytls_out_frame_t **out_last;
    size_t                   pending_out;
    ngx_uint_t               queued_frames;
    ngx_uint_t               free_pending_in_count;
    ngx_uint_t               direct_count;
    unsigned                 queued:1;
    unsigned                 ready_out:1;
    unsigned                 upstream_read_ready:1;
    unsigned                 upstream_write_ready:1;
    unsigned                 blocked_by_client:1;
    unsigned                 closing:1;
    unsigned                 in_closed:1;
    unsigned                 out_closed:1;
    unsigned                 fin_queued:1;
    unsigned                 fin_sent:1;
    unsigned                 synack_sent:1;
    unsigned                 first_psh_seen:1;
    unsigned                 input_blocked:1;
    unsigned                 input_exhausted:1;
    unsigned                 upstream_read_blocked:1;
    unsigned                 blocked_by_upstream:1;
    unsigned                 connect_pending:1;
    unsigned                 delayed_close:1;
    unsigned                 closed_by_protocol:1;
    unsigned                 pending_shutdown:1;

    u_char                  *initial_data;
    size_t                   initial_data_len;

    ngx_resolver_ctx_t      *resolver_ctx;
    ngx_uint_t               resolver_pending;
    ngx_anytls_resolve_target_e resolver_target;
    u_char                   resolver_domain[256];
    size_t                   resolver_domain_len;
    uint16_t                 resolver_port;

    /* UoT fields (owned by uot.c — prefer uot_private.h for layout) */
    ngx_connection_t        *udp;
    ngx_uint_t               udp_family;
    ngx_queue_t              uot_pending;
    ngx_uint_t               uot_pending_count;
    size_t                   uot_pending_bytes;
    ngx_anytls_addr_mode_e   uot_mode;
    u_char                  *uot_recv_buf;
    size_t                   uot_recv_pos;
    size_t                   uot_recv_len;
    size_t                   uot_recv_size;
    ngx_msec_t               uot_drop_log_time;
    ngx_uint_t               uot_drop_count;
    ngx_event_t             *uot_timer;
    ngx_msec_t               last_activity;
    unsigned                 uot_request_parsed:1;
};

#endif
