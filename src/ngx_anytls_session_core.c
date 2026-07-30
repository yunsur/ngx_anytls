#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_session_core.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_connection_private.h"


static ngx_int_t ngx_anytls_handle_psh(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_anytls_frame_t *frame,
    ngx_anytls_session_result_t *result);


static ngx_anytls_action_t *
ngx_anytls_session_add_action(ngx_anytls_session_result_t *result)
{
    ngx_anytls_action_t *a;

    if (result->action_count >= NGX_ANYTLS_SESSION_MAX_ACTIONS) {
        return NULL;
    }

    a = &result->actions[result->action_count];
    result->action_count++;
    ngx_memzero(a, sizeof(ngx_anytls_action_t));
    return a;
}


ngx_int_t
ngx_anytls_session_core_handle_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_frame_t *frame, ngx_anytls_session_result_t *result)
{
    ngx_anytls_stream_t *st;
    ngx_anytls_action_t *action;
    ngx_anytls_settings_t settings;
    ngx_str_t server_settings = ngx_string("v=2\n");

    ngx_memzero(result, sizeof(*result));

    switch (frame->cmd) {

    case NGX_ANYTLS_CMD_WASTE:
        return NGX_OK;

    case NGX_ANYTLS_CMD_SETTINGS:
        if (ngx_anytls_parse_settings(ac->pool, frame->data, frame->data_len,
                                       &settings) != NGX_OK)
        {
            return NGX_ERROR;
        }
        ac->settings_received = 1;
        ac->peer_version = settings.version;
        ac->state = NGX_ANYTLS_CONN_READY;

        if (ac->peer_version >= 2) {
            action = ngx_anytls_session_add_action(result);
            if (action == NULL) { return NGX_ERROR; }
            action->type = NGX_ANYTLS_ACTION_QUEUE_CONTROL;
            action->cmd = NGX_ANYTLS_CMD_SERVER_SETTINGS;
            action->stream_id = 0;
            action->data = server_settings.data;
            action->len = server_settings.len;
        }

        if (settings.padding_md5.len != 32
            || ngx_strncmp(settings.padding_md5.data, ac->conf->padding_md5, 32)
               != 0)
        {
            action = ngx_anytls_session_add_action(result);
            if (action == NULL) { return NGX_ERROR; }
            action->type = NGX_ANYTLS_ACTION_QUEUE_CONTROL;
            action->cmd = NGX_ANYTLS_CMD_UPDATE_PADDING;
            action->stream_id = 0;
            action->data = ac->conf->padding_data;
            action->len = ac->conf->padding_data_len;
        }
        return NGX_OK;

    case NGX_ANYTLS_CMD_HEART_REQUEST:
        action = ngx_anytls_session_add_action(result);
        if (action == NULL) { return NGX_ERROR; }
        action->type = NGX_ANYTLS_ACTION_QUEUE_CONTROL;
        action->cmd = NGX_ANYTLS_CMD_HEART_RESPONSE;
        action->stream_id = frame->stream_id;
        action->data = NULL;
        action->len = 0;
        return NGX_OK;

    case NGX_ANYTLS_CMD_HEART_RESPONSE:
        return NGX_OK;

    case NGX_ANYTLS_CMD_SYN:
        if (!ac->settings_received) {
            action = ngx_anytls_session_add_action(result);
            if (action == NULL) { return NGX_ERROR; }
            action->type = NGX_ANYTLS_ACTION_PROTOCOL_ERROR;
            action->data = (u_char *) "client did not send its settings";
            action->len = sizeof("client did not send its settings") - 1;
            return NGX_ERROR;
        }
        if (frame->stream_id == 0) {
            return NGX_ERROR;
        }
        if (ngx_anytls_stream_exists(ac, frame->stream_id)) {
            return NGX_OK;
        }
        st = ngx_anytls_stream_create(ac, frame->stream_id);
        return st ? NGX_OK : NGX_ERROR;

    case NGX_ANYTLS_CMD_PSH:
        st = ngx_anytls_stream_find(ac, frame->stream_id);
        if (st == NULL) {
            return NGX_OK;
        }
        if (st->in_closed || st->state == NGX_ANYTLS_STREAM_CLOSING
            || st->state == NGX_ANYTLS_STREAM_CLOSED)
        {
            return NGX_OK;
        }
        return ngx_anytls_handle_psh(ac, st, frame, result);

    case NGX_ANYTLS_CMD_FIN:
        st = ngx_anytls_stream_find(ac, frame->stream_id);
        if (st) {
            action = ngx_anytls_session_add_action(result);
            if (action == NULL) { return NGX_ERROR; }
            action->type = NGX_ANYTLS_ACTION_CLIENT_FIN;
            action->stream = st;
        }
        return NGX_OK;

    case NGX_ANYTLS_CMD_ALERT:
        if (frame->data_len == 0) {
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_INFO, ac->log, 0,
                      "anytls: alert from client: \"%*s\"",
                      (int) frame->data_len, frame->data);
        return NGX_DONE;

    case NGX_ANYTLS_CMD_SYNACK:
    case NGX_ANYTLS_CMD_UPDATE_PADDING:
    case NGX_ANYTLS_CMD_SERVER_SETTINGS:
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ac->log, 0,
                       "anytls: ignored client control frame %s, stream:%ui",
                       ngx_anytls_cmd_name(frame->cmd),
                       (ngx_uint_t) frame->stream_id);
        return NGX_OK;

    default:
        return NGX_OK;
    }
}


static ngx_int_t
ngx_anytls_handle_psh(ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st,
    ngx_anytls_frame_t *frame, ngx_anytls_session_result_t *result)
{
    ngx_int_t rc;
    ngx_anytls_addr_t addr;
    u_char *payload;
    size_t payload_len;
    ngx_anytls_action_t *action;

    if (!st->first_psh_seen) {
        ngx_pool_t *pool;
        pool = ngx_anytls_stream_pool(st);
        if (pool == NULL) { return NGX_ERROR; }
        rc = ngx_anytls_parse_socksaddr(pool, frame->data, frame->data_len,
                                         &addr);
        if (rc != NGX_OK) {
            return rc;
        }
        st->first_psh_seen = 1;
        ngx_anytls_addr_copy(&st->target, &addr);
        payload = frame->data + addr.consumed;
        payload_len = frame->data_len - addr.consumed;

        action = ngx_anytls_session_add_action(result);
        if (action == NULL) { return NGX_ERROR; }
        action->type = NGX_ANYTLS_ACTION_OPEN_UPSTREAM;
        action->stream = st;
        ngx_anytls_addr_copy(&action->addr, &addr);
        action->data = payload;
        action->len = payload_len;

        return NGX_OK;
    }

    action = ngx_anytls_session_add_action(result);
    if (action == NULL) { return NGX_ERROR; }
    action->type = NGX_ANYTLS_ACTION_FORWARD_CLIENT_PAYLOAD;
    action->stream = st;
    action->data = frame->data;
    action->len = frame->data_len;

    return NGX_OK;
}
