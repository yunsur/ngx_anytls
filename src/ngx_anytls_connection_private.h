#ifndef NGX_ANYTLS_PRIVATE_H_INCLUDED
#define NGX_ANYTLS_PRIVATE_H_INCLUDED

/* Private struct definitions.
 *
 * Include this directly from .c files that need access to
 * the full connection/stream/srv_conf struct layouts.
 * The module header (ngx_stream_anytls_module.h) does NOT
 * include this file. */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event_connect.h>

#include "ngx_stream_anytls_module.h"
#include "ngx_anytls_session_core.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"
#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_upstream_state.h"

/* Subsystem private headers — struct layouts moved to dedicated files */
#include "ngx_anytls_client_mux_private.h"
#include "ngx_anytls_uot_private.h"
#include "ngx_anytls_upstream_mux_private.h"
#include "ngx_anytls_stream_private.h"
#include "ngx_anytls_fallback_private.h"


typedef struct ngx_stream_anytls_srv_conf_s {
    ngx_flag_t               enabled;
    ngx_flag_t               reject_plain_http;
    ngx_flag_t               password_set;
    u_char                   password_hash[32];
    ngx_str_t                padding_file;
    u_char                  *padding_data;
    size_t                   padding_data_len;
    u_char                   padding_md5[33];
    ngx_stream_complex_value_t *fallback;
    ngx_flag_t               fallback_proxy_protocol;
    ngx_flag_t               fallback_proxy_protocol_set;
    ngx_msec_t               fallback_connect_timeout;
    ngx_msec_t               upstream_connect_timeout;
    ngx_msec_t               handshake_timeout;
    size_t                   buffer_size;
    ngx_uint_t               max_streams;
    size_t                   max_pending_output;
    size_t                   max_pending_input;
    ngx_resolver_t          *resolver;
    ngx_msec_t               resolver_timeout;
    ngx_msec_t               write_timeout;
    ngx_msec_t               uot_idle_timeout;
    ngx_uint_t               uot_pending_packets;
    size_t                   uot_pending_bytes;
} ngx_stream_anytls_srv_conf_t;

struct ngx_anytls_connection_s {
    ngx_stream_session_t    *session;
    ngx_connection_t        *client;
    ngx_pool_t              *pool;
    ngx_log_t               *log;
    ngx_stream_anytls_srv_conf_t *conf;
    ngx_anytls_conn_state_e  state;

    ngx_anytls_stream_t    **stream_ht;
    uint32_t                 stream_ht_mask;
    ngx_queue_t              stream_list;
    ngx_queue_t              ready_streams;
    ngx_queue_t              blocked_upstream_reads;
    ngx_uint_t               active_streams;
    ngx_uint_t               blocked_input_streams;

    ngx_anytls_out_frame_t  *control_out;
    ngx_anytls_out_frame_t **control_out_last;
    ngx_anytls_out_frame_t  *data_out;
    ngx_anytls_out_frame_t **data_out_last;
    ngx_anytls_out_frame_t  *sending;
    ngx_anytls_out_frame_t **sending_last;
    ngx_anytls_out_frame_t  *free_frames;
    ngx_uint_t               free_frames_count;
    ngx_uint_t               frames;

    ngx_queue_t              closing_streams;
    ngx_uint_t               resumed_streams;

    ngx_anytls_upstream_mux_t upstream_mux;
    ngx_event_t              write_timer;
    ngx_chain_t             *unsent;
    size_t                   pending_output;
    size_t                   pending_input;

    ngx_chain_t             *free_read_bufs;
    ngx_uint_t               free_read_bufs_count;
    void                    *free_pending_bufs;
    ngx_uint_t               free_pending_bufs_count;

    u_char                  *read_buf;
    size_t                   read_buf_size;

    size_t                   remnant_len;

    u_char                   auth[NGX_ANYTLS_AUTH_BUF_SIZE];
    size_t                   auth_len;
    uint16_t                 auth_padding_len;

    ngx_anytls_session_core_t  session_core;
    unsigned                 authenticated:1;
    /* NB: settings_received, peer_version, state -> session_core */
    unsigned                 client_eof:1;
    unsigned                 client_read_blocked:1;
    unsigned                 input_paused:1;
    unsigned                 write_pending:1;
    unsigned                 output_pressure:1;
    unsigned                 closing:1;

    ngx_peer_connection_t    fallback_peer;
    ngx_connection_t        *fallback;
    ngx_buf_t               *fallback_replay;
    ngx_buf_t               *fallback_client_buf;
    ngx_buf_t               *fallback_upstream_buf;
    ngx_anytls_upstream_state_tracker_t fallback_state;
    unsigned                 fallback_connected:1;
};
#endif /* NGX_ANYTLS_PRIVATE_H_INCLUDED */
