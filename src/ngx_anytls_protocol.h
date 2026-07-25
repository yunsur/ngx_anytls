#ifndef NGX_ANYTLS_PROTOCOL_H_INCLUDED
#define NGX_ANYTLS_PROTOCOL_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_ANYTLS_AUTH_HASH_LEN       32
#define NGX_ANYTLS_FRAME_HEADER_LEN    7
#define NGX_ANYTLS_MAX_FRAME_DATA      65535
#define NGX_ANYTLS_VERSION             2

typedef enum {
    NGX_ANYTLS_CMD_WASTE           = 0,
    NGX_ANYTLS_CMD_SYN             = 1,
    NGX_ANYTLS_CMD_PSH             = 2,
    NGX_ANYTLS_CMD_FIN             = 3,
    NGX_ANYTLS_CMD_SETTINGS        = 4,
    NGX_ANYTLS_CMD_ALERT           = 5,
    NGX_ANYTLS_CMD_UPDATE_PADDING  = 6,
    NGX_ANYTLS_CMD_SYNACK          = 7,
    NGX_ANYTLS_CMD_HEART_REQUEST   = 8,
    NGX_ANYTLS_CMD_HEART_RESPONSE  = 9,
    NGX_ANYTLS_CMD_SERVER_SETTINGS = 10
} ngx_anytls_cmd_e;

typedef struct {
    ngx_uint_t  cmd;
    uint32_t    stream_id;
    uint16_t    data_len;
    u_char     *data;
} ngx_anytls_frame_t;

typedef struct {
    ngx_uint_t  version;
    ngx_str_t   client;
    ngx_str_t   padding_md5;
} ngx_anytls_settings_t;

void ngx_anytls_sha256(ngx_str_t *password, u_char out[32]);
void ngx_anytls_md5_hex(u_char *data, size_t len, u_char out[33]);
ngx_int_t ngx_anytls_parse_frame(u_char *pos, u_char *last,
    ngx_anytls_frame_t *frame, size_t *consumed);
u_char *ngx_anytls_write_frame_header(u_char *p, ngx_uint_t cmd,
    uint32_t stream_id, uint16_t len);
ngx_int_t ngx_anytls_parse_settings(ngx_pool_t *pool, u_char *data, size_t len,
    ngx_anytls_settings_t *settings);
const char *ngx_anytls_cmd_name(ngx_uint_t cmd);

#endif
