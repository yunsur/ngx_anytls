#ifndef NGX_ANYTLS_SESSION_CORE_H_INCLUDED
#define NGX_ANYTLS_SESSION_CORE_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;
struct ngx_anytls_stream_s;
typedef struct ngx_anytls_stream_s ngx_anytls_stream_t;

#define NGX_ANYTLS_SESSION_MAX_ACTIONS   4

typedef enum {
    NGX_ANYTLS_ACTION_NONE = 0,
    NGX_ANYTLS_ACTION_QUEUE_CONTROL,
    NGX_ANYTLS_ACTION_OPEN_UPSTREAM,
    NGX_ANYTLS_ACTION_FORWARD_CLIENT_PAYLOAD,
    NGX_ANYTLS_ACTION_CLIENT_FIN,
    NGX_ANYTLS_ACTION_PROTOCOL_ERROR
} ngx_anytls_action_type_e;

typedef struct {
    ngx_anytls_action_type_e  type;
    ngx_uint_t                cmd;
    uint32_t                  stream_id;
    ngx_anytls_stream_t      *stream;
    ngx_anytls_addr_t         addr;
    u_char                   *data;
    size_t                    len;
} ngx_anytls_action_t;

typedef struct {
    ngx_anytls_action_t       actions[NGX_ANYTLS_SESSION_MAX_ACTIONS];
    ngx_uint_t                action_count;
} ngx_anytls_session_result_t;


ngx_int_t ngx_anytls_session_core_handle_frame(
    ngx_anytls_connection_t *ac,
    ngx_anytls_frame_t *frame,
    ngx_anytls_session_result_t *result);

#endif
