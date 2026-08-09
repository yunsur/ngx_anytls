#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_session_core.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"


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


void
ngx_anytls_session_core_init(ngx_anytls_session_core_t *core,
    u_char *padding_md5, u_char *padding_data, size_t padding_data_len)
{
    ngx_memzero(core, sizeof(*core));
    core->state = NGX_ANYTLS_CONN_AUTH;
    core->peer_version = 1;   /* default: assume v1 until SETTINGS */
    core->padding_md5 = padding_md5;
    core->padding_data = padding_data;
    core->padding_data_len = padding_data_len;
}


ngx_int_t
ngx_anytls_session_core_handle_frame(ngx_anytls_session_core_t *core,
    ngx_pool_t *pool, ngx_log_t *log,
    ngx_anytls_frame_t *frame, ngx_anytls_session_result_t *result)
{
    ngx_anytls_action_t *action;
    ngx_anytls_settings_t settings;
    ngx_str_t server_settings = ngx_string("v=2");

    result->action_count = 0;

    switch (frame->cmd) {

    case NGX_ANYTLS_CMD_WASTE:
        return NGX_OK;

    case NGX_ANYTLS_CMD_SETTINGS:
        if (ngx_anytls_parse_settings(pool, frame->data, frame->data_len,
                                       &settings) != NGX_OK)
        {
            return NGX_ERROR;
        }
        core->settings_received = 1;
        core->peer_version = settings.version;
        core->state = NGX_ANYTLS_CONN_READY;

        if (settings.padding_md5.len != 32
            || ngx_strncmp(settings.padding_md5.data, core->padding_md5, 32)
               != 0)
        {
            action = ngx_anytls_session_add_action(result);
            if (action == NULL) { return NGX_ERROR; }
            action->type = NGX_ANYTLS_ACTION_QUEUE_CONTROL;
            action->cmd = NGX_ANYTLS_CMD_UPDATE_PADDING;
            action->stream_id = 0;
            action->data = core->padding_data;
            action->len = core->padding_data_len;
        }

        if (core->peer_version >= 2) {
            action = ngx_anytls_session_add_action(result);
            if (action == NULL) { return NGX_ERROR; }
            action->type = NGX_ANYTLS_ACTION_QUEUE_CONTROL;
            action->cmd = NGX_ANYTLS_CMD_SERVER_SETTINGS;
            action->stream_id = 0;
            action->data = server_settings.data;
            action->len = server_settings.len;
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
        if (!core->settings_received) {
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
        action = ngx_anytls_session_add_action(result);
        if (action == NULL) { return NGX_ERROR; }
        action->type = NGX_ANYTLS_ACTION_OPEN_STREAM;
        action->stream_id = frame->stream_id;
        return NGX_OK;

    case NGX_ANYTLS_CMD_PSH:
        action = ngx_anytls_session_add_action(result);
        if (action == NULL) { return NGX_ERROR; }
        action->type = NGX_ANYTLS_ACTION_FORWARD_CLIENT_PAYLOAD;
        action->stream_id = frame->stream_id;
        action->data = frame->data;
        action->len = frame->data_len;
        return NGX_OK;

    case NGX_ANYTLS_CMD_FIN:
        action = ngx_anytls_session_add_action(result);
        if (action == NULL) { return NGX_ERROR; }
        action->type = NGX_ANYTLS_ACTION_CLIENT_FIN;
        action->stream_id = frame->stream_id;
        return NGX_OK;

    case NGX_ANYTLS_CMD_ALERT:
        if (frame->data_len == 0) {
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "anytls: alert from client: \"%*s\"",
                      (int) frame->data_len, frame->data);
        action = ngx_anytls_session_add_action(result);
        if (action == NULL) { return NGX_ERROR; }
        action->type = NGX_ANYTLS_ACTION_CLIENT_ALERT;
        action->data = frame->data;
        action->len = frame->data_len;
        return NGX_OK;

    case NGX_ANYTLS_CMD_SYNACK:
    case NGX_ANYTLS_CMD_UPDATE_PADDING:
    case NGX_ANYTLS_CMD_SERVER_SETTINGS:
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                       "anytls: ignored client control frame %s, stream:%ui",
                       ngx_anytls_cmd_name(frame->cmd),
                       (ngx_uint_t) frame->stream_id);
        return NGX_OK;

    default:
        return NGX_OK;
    }
}


ngx_int_t
ngx_anytls_session_core_parse_first_psh(
    ngx_pool_t *pool,
    u_char *data, size_t data_len,
    ngx_anytls_addr_t *addr,
    u_char **payload, size_t *payload_len)
{
    ngx_int_t rc;

    rc = ngx_anytls_parse_socksaddr(pool, data, data_len, addr);
    if (rc != NGX_OK) {
        return rc;
    }

    *payload = data + addr->consumed;
    *payload_len = data_len - addr->consumed;
    return NGX_OK;
}
