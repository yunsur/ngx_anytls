#ifndef NGX_STREAM_ANYTLS_MODULE_H_INCLUDED
#define NGX_STREAM_ANYTLS_MODULE_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event_connect.h>

#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"

extern ngx_module_t ngx_stream_anytls_module;

#define NGX_ANYTLS_AUTH_BUF_SIZE       (32 + 2 + 65535)
#define NGX_ANYTLS_READ_BUF_SIZE       65536
#define NGX_ANYTLS_STREAM_POOL_SIZE    4096
#define NGX_ANYTLS_PADDING_MAX_SIZE    (1024 * 1024)
#define NGX_ANYTLS_DEFAULT_BUF_SIZE    65535
#define NGX_ANYTLS_DEFAULT_MAX_STREAMS 1024
#define NGX_ANYTLS_DEFAULT_MAX_PENDING (8 * 1024 * 1024)
#define NGX_ANYTLS_DEFAULT_MAX_PENDING_INPUT (8 * 1024 * 1024)
#define NGX_ANYTLS_DEFAULT_UOT_PENDING_PACKETS 256
#define NGX_ANYTLS_DEFAULT_UOT_PENDING_BYTES (512 * 1024)
#define NGX_ANYTLS_MAX_OUT_FRAMES      10000
#define NGX_ANYTLS_MAX_STREAM_FRAMES   1024
#define NGX_ANYTLS_MAX_FREE_FRAMES     1024
#define NGX_ANYTLS_MAX_FREE_READ_BUFS  32
#define NGX_ANYTLS_MAX_FREE_PENDING_IN 64
#define NGX_ANYTLS_MIN_SCHEDULE_FRAMES 16
#define NGX_ANYTLS_MAX_SCHEDULE_BYTES  (1024 * 1024)
#define NGX_ANYTLS_DEFAULT_WRITE_TIMEOUT 60000
#define NGX_ANYTLS_DEFAULT_PADDING                                           \
    "stop=8\n"                                                              \
    "0=30-30\n"                                                            \
    "1=100-400\n"                                                          \
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"              \
    "3=9-9,500-1000\n"                                                     \
    "4=500-1000\n"                                                         \
    "5=500-1000\n"                                                         \
    "6=500-1000\n"                                                         \
    "7=500-1000\n"


#define NGX_ANYTLS_MAX_DIRECT_FRAMES 4

typedef enum {
    NGX_ANYTLS_CONN_AUTH = 0,
    NGX_ANYTLS_CONN_SETTINGS,
    NGX_ANYTLS_CONN_READY,
    NGX_ANYTLS_CONN_FALLBACK,
    NGX_ANYTLS_CONN_CLOSING
} ngx_anytls_conn_state_e;

typedef enum {
    NGX_ANYTLS_STREAM_INIT = 0,
    NGX_ANYTLS_STREAM_CONNECTING,
    NGX_ANYTLS_STREAM_CONNECTED,
    NGX_ANYTLS_STREAM_HALF_CLOSED,
    NGX_ANYTLS_STREAM_CLOSING,
    NGX_ANYTLS_STREAM_CLOSED
} ngx_anytls_stream_state_e;

typedef enum {
    NGX_ANYTLS_UPSTREAM_TCP = 0,
    NGX_ANYTLS_UPSTREAM_UOT
} ngx_anytls_upstream_type_e;

typedef enum {
    NGX_ANYTLS_RESOLVE_NONE = 0,
    NGX_ANYTLS_RESOLVE_TCP,
    NGX_ANYTLS_RESOLVE_UOT_CONNECT,
    NGX_ANYTLS_RESOLVE_UOT_PACKET
} ngx_anytls_resolve_target_e;

typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;
typedef struct ngx_anytls_stream_s ngx_anytls_stream_t;
typedef struct ngx_anytls_out_frame_s ngx_anytls_out_frame_t;
typedef struct ngx_anytls_pending_s ngx_anytls_pending_t;
typedef struct ngx_anytls_upstream_mux_s ngx_anytls_upstream_mux_t;
typedef void (*ngx_anytls_frame_handler_pt)(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *frame);

typedef struct {
    ngx_uint_t               index;
    ngx_msec_t               start_time;
    off_t                    bytes_sent;
    off_t                    bytes_received;
    unsigned                 opened:1;
    unsigned                 finalized:1;
} ngx_anytls_upstream_state_tracker_t;

struct ngx_anytls_out_frame_s {
    ngx_anytls_out_frame_t  *next;
    ngx_chain_t             *first;
    ngx_chain_t             *last;
    ngx_chain_t             *payload;
    ngx_anytls_stream_t     *stream;
    ngx_anytls_frame_handler_pt handler;
    size_t                   length;
    ngx_uint_t               cmd;
    ngx_chain_t              header_chain;
    ngx_buf_t                header_buf;
    u_char                   header[NGX_ANYTLS_FRAME_HEADER_LEN];
    ngx_chain_t              payload_chain;
    ngx_buf_t                payload_buf;
    unsigned                 blocked:1;
    unsigned                 fin:1;
    unsigned                 own_payload:1;
    unsigned                 recycle_payload:1;
};

struct ngx_anytls_pending_s {
    ngx_anytls_pending_t    *next;
    u_char                  *data;
    size_t                   len;
    size_t                   sent;
};

typedef struct {
    ngx_queue_t              queue;
    u_char                  *domain;
    size_t                   domain_len;
    uint16_t                 port;
    u_char                  *payload;
    size_t                   payload_len;
} ngx_anytls_uot_pending_t;

struct ngx_anytls_upstream_mux_s {
    ngx_queue_t              read_ready;
    ngx_queue_t              write_ready;
    ngx_queue_t              connect_pending;
};


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

typedef struct {
    ngx_flag_t               enabled;
    ngx_flag_t               password_set;
    u_char                   password_hash[32];
    ngx_str_t                padding_file;
    u_char                  *padding_data;
    size_t                   padding_data_len;
    u_char                   padding_md5[33];
    ngx_stream_complex_value_t *fallback;
    ngx_flag_t               fallback_proxy_protocol;
    ngx_flag_t               fallback_proxy_protocol_set;
    size_t                   buffer_size;
    ngx_uint_t               max_streams;
    size_t                   max_pending_output;
    size_t                   max_pending_input;
    ngx_resolver_t          *resolver;
    ngx_msec_t               resolver_timeout;
    ngx_msec_t               write_timeout;
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

    ngx_uint_t               peer_version;
    unsigned                 authenticated:1;
    unsigned                 settings_received:1;
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
};

void ngx_anytls_client_read_handler(ngx_event_t *rev);
void ngx_anytls_client_write_handler(ngx_event_t *wev);
void ngx_anytls_upstream_read_handler(ngx_event_t *rev);
void ngx_anytls_upstream_write_handler(ngx_event_t *wev);
void ngx_anytls_udp_read_handler(ngx_event_t *rev);
void ngx_anytls_udp_write_handler(ngx_event_t *wev);
void ngx_anytls_finalize(ngx_anytls_connection_t *ac);

/* Mux scheduler API */
ngx_int_t ngx_anytls_mux_queue_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len);
void ngx_anytls_mux_on_client_writable(ngx_anytls_connection_t *ac);
ngx_int_t ngx_anytls_mux_mark_closing(ngx_anytls_stream_t *st);



#endif
