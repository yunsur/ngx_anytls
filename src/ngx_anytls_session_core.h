#ifndef NGX_ANYTLS_SESSION_CORE_H_INCLUDED
#define NGX_ANYTLS_SESSION_CORE_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"

/* Connection state enum — canonical definition lives here.
 * Connection/session shared state; no module.h dependency. */
typedef enum {
    NGX_ANYTLS_CONN_AUTH = 0,
    NGX_ANYTLS_CONN_SETTINGS,
    NGX_ANYTLS_CONN_READY,
    NGX_ANYTLS_CONN_FALLBACK,
    NGX_ANYTLS_CONN_CLOSING
} ngx_anytls_conn_state_e;

#define NGX_ANYTLS_SESSION_MAX_ACTIONS   4

typedef enum {
    NGX_ANYTLS_ACTION_NONE = 0,
    NGX_ANYTLS_ACTION_QUEUE_CONTROL,
    NGX_ANYTLS_ACTION_OPEN_STREAM,         /* dispatcher creates stream */
    NGX_ANYTLS_ACTION_FORWARD_CLIENT_PAYLOAD,
    NGX_ANYTLS_ACTION_CLIENT_FIN,
    NGX_ANYTLS_ACTION_PROTOCOL_ERROR,
    NGX_ANYTLS_ACTION_CLIENT_ALERT
} ngx_anytls_action_type_e;

typedef struct {
    ngx_anytls_action_type_e  type;
    ngx_uint_t                cmd;
    uint32_t                  stream_id;   /* used by dispatcher to resolve */
    ngx_anytls_addr_t         addr;
    u_char                   *data;
    size_t                    len;
} ngx_anytls_action_t;

typedef struct {
    ngx_anytls_action_t       actions[NGX_ANYTLS_SESSION_MAX_ACTIONS];
    ngx_uint_t                action_count;
} ngx_anytls_session_result_t;


/* Protocol session state — extracted from connection for isolation. */
typedef struct {
    unsigned     settings_received:1;
    ngx_uint_t   peer_version;
    ngx_anytls_conn_state_e state;
    u_char      *padding_md5;      /* points to conf->padding_md5, 32 bytes */
    u_char      *padding_data;
    size_t       padding_data_len;
} ngx_anytls_session_core_t;


/* --- Session core API --- */

void ngx_anytls_session_core_init(ngx_anytls_session_core_t *core,
    u_char *padding_md5, u_char *padding_data, size_t padding_data_len);

ngx_int_t ngx_anytls_session_core_handle_frame(
    ngx_anytls_session_core_t *core,
    ngx_pool_t *pool,
    ngx_log_t *log,
    ngx_anytls_frame_t *frame,
    ngx_anytls_session_result_t *result);

/* Parse a first-PSH frame: extracts SOCKS address and remaining payload.
 * Called by the dispatcher after stream lookup and first_psh detection.
 * Returns NGX_OK on success; addr->consumed reports how many bytes were
 * consumed by the address.  On failure returns NGX_ERROR. */
ngx_int_t ngx_anytls_session_core_parse_first_psh(
    ngx_pool_t *pool,
    u_char *data, size_t data_len,
    ngx_anytls_addr_t *addr,
    u_char **payload, size_t *payload_len);


#endif
