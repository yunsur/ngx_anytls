#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_session_actions.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_connection.h"
#include "ngx_anytls_connection_private.h"


ngx_int_t
ngx_anytls_session_actions_run(ngx_anytls_connection_t *ac,
    ngx_anytls_session_result_t *result,
    ngx_anytls_session_actions_outcome_t *outcome)
{
    ngx_int_t   rc = NGX_OK;
    ngx_uint_t  i;

    for (i = 0; i < result->action_count && !outcome->done; i++) {
        ngx_int_t              act_rc = NGX_OK;
        ngx_anytls_action_t   *a = &result->actions[i];
        ngx_anytls_stream_t   *st;

        switch (a->type) {
        case NGX_ANYTLS_ACTION_QUEUE_CONTROL:
            act_rc = ngx_anytls_client_mux_queue_ref_frame(ac, NULL,
                a->cmd, a->stream_id, a->data, a->len);
            break;

        case NGX_ANYTLS_ACTION_OPEN_STREAM:
            /* SYN: core validated settings_received and stream_id;
             * dispatcher checks duplicate and creates stream. */
            if (ngx_anytls_stream_resolve(ac, a->stream_id,
                    NGX_ANYTLS_STREAM_OP_EXISTS))
            {
                break;  /* duplicate SYN, ignore */
            }
            st = ngx_anytls_stream_resolve(ac, a->stream_id,
                    NGX_ANYTLS_STREAM_OP_CREATE);
            if (st == NULL) {
                act_rc = NGX_ERROR;
            }
            break;


        case NGX_ANYTLS_ACTION_FORWARD_CLIENT_PAYLOAD:
            /* Core marks every PSH as FORWARD_CLIENT_PAYLOAD.
             * Dispatcher resolves stream and handles first-PSH. */
            st = ngx_anytls_stream_resolve(ac, a->stream_id,
                    NGX_ANYTLS_STREAM_OP_FIND);
            if (st == NULL) { break; }
            if (!ngx_anytls_stream_can_accept_payload(st)) {
                break;
            }
            if (ngx_anytls_stream_is_first_psh(st)) {
                ngx_pool_t *spool = ngx_anytls_stream_pool(st);
                u_char *payload;
                size_t payload_len;
                if (spool == NULL) { act_rc = NGX_ERROR; break; }
                act_rc = ngx_anytls_session_core_parse_first_psh(
                    spool, a->data, a->len,
                    &a->addr, &payload, &payload_len);
                if (act_rc != NGX_OK) { break; }
                ngx_anytls_stream_set_first_psh(st, &a->addr);
                act_rc = ngx_anytls_upstream_mux_handle_first_psh(ac,
                    st, &a->addr, payload, payload_len);
            } else {
                act_rc = ngx_anytls_upstream_mux_handle_client_payload(
                    st, a->data, a->len);
            }
            break;

        case NGX_ANYTLS_ACTION_CLIENT_FIN:
            st = ngx_anytls_stream_resolve(ac, a->stream_id,
                    NGX_ANYTLS_STREAM_OP_FIND);
            if (st) {
                ngx_anytls_upstream_mux_handle_client_fin(ac, st);
            }
            break;

        case NGX_ANYTLS_ACTION_CLIENT_ALERT:
            (void) ngx_anytls_client_mux_drain(ac, 0, NULL);
            ngx_anytls_finalize(ac);
            outcome->done = 1;
            break;

        case NGX_ANYTLS_ACTION_PROTOCOL_ERROR:
            if (a->len) {
                (void) ngx_anytls_client_mux_queue_error(ac, NULL,
                    a->data, a->len);
            }
            (void) ngx_anytls_client_mux_drain(ac, 0, NULL);
            ngx_anytls_finalize(ac);
            outcome->done = 1;
            break;

        default:
            break;
        }

        if (act_rc != NGX_OK && rc == NGX_OK) {
            rc = act_rc;
        }
    }

    return rc;
}
