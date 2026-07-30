#ifndef NGX_ANYTLS_AUTH_H_INCLUDED
#define NGX_ANYTLS_AUTH_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_ANYTLS_AUTH_BUF_SIZE       (32 + 2 + 65535)

typedef enum {
    NGX_ANYTLS_AUTH_MORE = 0,
    NGX_ANYTLS_AUTH_OK,
    NGX_ANYTLS_AUTH_FALLBACK,
    NGX_ANYTLS_AUTH_REJECT,
    NGX_ANYTLS_AUTH_ERROR
} ngx_anytls_auth_result_e;

typedef struct {
    ngx_anytls_auth_result_e  result;
    size_t                    consumed;
    u_char                   *fallback_replay;
    size_t                    fallback_replay_len;
} ngx_anytls_auth_step_t;

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;

ngx_anytls_auth_step_t ngx_anytls_auth_process(
    ngx_anytls_connection_t *ac,
    u_char *data,
    size_t len);

#endif
