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
                u_char *pdata = a->data;
                size_t plen = a->len;
                size_t old_acc_len = 0;
                if (spool == NULL) { act_rc = NGX_ERROR; break; }

                if (st->first_psh_acc_len) {
                    /* partial address already buffered: append only what
                     * the address can still need; any payload bytes of
                     * this frame stay in the frame and are picked up
                     * below from addr.consumed */
                    if (a->len == 0) {
                        /* no progress: ignore and keep waiting */
                        act_rc = NGX_OK;
                        break;
                    }
                    old_acc_len = st->first_psh_acc_len;
                    plen = ngx_min(a->len, NGX_ANYTLS_MAX_SOCKS_ADDR_LEN
                                              - old_acc_len);
                    ngx_memcpy(st->first_psh_acc + old_acc_len,
                               a->data, plen);
                    st->first_psh_acc_len += plen;
                    pdata = st->first_psh_acc;
                    plen = st->first_psh_acc_len;
                    st->first_psh_acc_len = 0;
                }

                act_rc = ngx_anytls_session_core_parse_first_psh(
                    spool, pdata, plen,
                    &a->addr, &payload, &payload_len);
                if (act_rc == NGX_AGAIN) {
                    /* partial address: keep the bytes for the next PSH;
                     * this is not a connection error.  Allocate the
                     * fixed-size buffer once, then append in place, so a
                     * 1-byte-per-PSH attacker pays one allocation per
                     * stream instead of O(n^2) copies.  A buffer full of
                     * address bytes that still does not parse is illegal. */
                    if (plen >= NGX_ANYTLS_MAX_SOCKS_ADDR_LEN) {
                        act_rc = NGX_ERROR;
                        break;
                    }
                    if (st->first_psh_acc == NULL) {
                        st->first_psh_acc =
                            ngx_pnalloc(spool,
                                        NGX_ANYTLS_MAX_SOCKS_ADDR_LEN);
                        if (st->first_psh_acc == NULL) {
                            act_rc = NGX_ERROR;
                            break;
                        }
                    }
                    if (pdata != st->first_psh_acc) {
                        ngx_memcpy(st->first_psh_acc, pdata, plen);
                    }
                    st->first_psh_acc_len = plen;
                    act_rc = NGX_OK;
                    break;
                }
                if (act_rc != NGX_OK) { break; }
                ngx_anytls_stream_set_first_psh(st, &a->addr);

                if (pdata != a->data) {
                    /* address completed across frames: the payload is the
                     * remainder of the current frame after the address
                     * bytes it contributed */
                    size_t from_frame = a->addr.consumed > old_acc_len
                        ? a->addr.consumed - old_acc_len : 0;
                    payload = a->data + from_frame;
                    payload_len = a->len - from_frame;
                } else {
                    payload = pdata + a->addr.consumed;
                    payload_len = plen - a->addr.consumed;
                }

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
