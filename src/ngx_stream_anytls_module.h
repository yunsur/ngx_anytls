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
#define NGX_ANYTLS_DEFAULT_FALLBACK_CONNECT_TIMEOUT 60000
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
typedef struct ngx_stream_anytls_srv_conf_s ngx_stream_anytls_srv_conf_t;

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

void ngx_anytls_client_read_handler(ngx_event_t *rev);
void ngx_anytls_client_write_handler(ngx_event_t *wev);
void ngx_anytls_upstream_read_handler(ngx_event_t *rev);
void ngx_anytls_upstream_write_handler(ngx_event_t *wev);
void ngx_anytls_udp_read_handler(ngx_event_t *rev);
void ngx_anytls_udp_write_handler(ngx_event_t *wev);
void ngx_anytls_finalize(ngx_anytls_connection_t *ac);
void ngx_anytls_finalize_rc(ngx_anytls_connection_t *ac, ngx_uint_t rc);



#endif /* NGX_STREAM_ANYTLS_MODULE_H_INCLUDED */
