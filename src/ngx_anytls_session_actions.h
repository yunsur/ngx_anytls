#ifndef NGX_ANYTLS_SESSION_ACTIONS_H_INCLUDED
#define NGX_ANYTLS_SESSION_ACTIONS_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_anytls_session_core.h"

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;

typedef struct {
    unsigned done:1;   /* caller MUST stop processing and return NGX_ERROR */
} ngx_anytls_session_actions_outcome_t;

ngx_int_t ngx_anytls_session_actions_run(
    ngx_anytls_connection_t *ac,
    ngx_anytls_session_result_t *result,
    ngx_anytls_session_actions_outcome_t *outcome);

#endif
