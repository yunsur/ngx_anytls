#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_client_handler.h"
#include "ngx_anytls_auth.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_fallback.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_connection.h"
#include "ngx_anytls_session_core.h"
#include "ngx_anytls_session_actions.h"
#include "ngx_anytls_connection_private.h"


static void ngx_anytls_send_http_400(ngx_anytls_connection_t *ac);
static ngx_int_t ngx_anytls_enable_client_read(ngx_anytls_connection_t *ac);
static ngx_uint_t ngx_anytls_input_blocked(ngx_anytls_connection_t *ac);


ngx_int_t
ngx_anytls_process_client_bytes(ngx_anytls_connection_t *ac, u_char *data,
    size_t len)
{
    u_char *pos, *last;
    ngx_int_t rc;
    ngx_anytls_frame_t frame;
    size_t consumed;

    if (!ac->authenticated) {
        if (data == NULL) {
            return NGX_ERROR;
        }

        ngx_anytls_auth_step_t auth_result = ngx_anytls_auth_process(ac, data, len);
        data += auth_result.consumed;
        len -= auth_result.consumed;

        if (auth_result.result == NGX_ANYTLS_AUTH_MORE) {
            return NGX_OK;
        }
        if (auth_result.result == NGX_ANYTLS_AUTH_FALLBACK) {
            if (ac->conf->fallback == NULL) {
                ngx_anytls_send_http_400(ac);
                return NGX_ERROR;
            }
            if (ngx_anytls_fallback_start(ac, auth_result.fallback_replay,
                                           auth_result.fallback_replay_len) != NGX_OK)
            {
                return NGX_ERROR;
            }
            return NGX_OK;
        }
        if (auth_result.result != NGX_ANYTLS_AUTH_OK) {
            return NGX_ERROR;
        }
    }

    if (len == 0) {
        return NGX_OK;
    }

    pos = data;
    last = data + len;

    for ( ;; ) {
        ngx_anytls_session_result_t session_result;

        rc = ngx_anytls_parse_frame(pos, last, &frame, &consumed);
        if (rc == NGX_AGAIN) {
            break;
        }
        if (rc != NGX_OK) {
            ac->remnant_len = 0;
            return NGX_ERROR;
        }

        rc = ngx_anytls_session_core_handle_frame(&ac->session_core,
            ac->pool, ac->log, &frame, &session_result);

        {
            ngx_anytls_session_actions_outcome_t outcome;
            ngx_int_t act_rc;

            ngx_memzero(&outcome, sizeof(outcome));
            act_rc = ngx_anytls_session_actions_run(ac, &session_result,
                                                     &outcome);
            if (outcome.done) {
                ac->remnant_len = 0;
                return NGX_ERROR;
            }
            if (act_rc != NGX_OK && rc == NGX_OK) {
                rc = act_rc;
            }
        }

        if (rc != NGX_OK) {
            ac->remnant_len = 0;
            return rc;
        }

        pos += consumed;

        if (ac->input_paused) {
            break;
        }
    }

    /* Compact any incomplete frame to start of read_buf (remnant) */
    ac->remnant_len = (size_t) (last - pos);
    if (ac->remnant_len) {
        ngx_memmove(ac->read_buf, pos, ac->remnant_len);
    }

    return NGX_OK;
}


ngx_int_t
ngx_anytls_client_input_pause(ngx_anytls_connection_t *ac)
{
    ngx_event_t *rev;

    ac->input_paused = 1;

    if (ac->client == NULL || ac->client_read_blocked) {
        return NGX_OK;
    }

    rev = ac->client->read;
    ac->client_read_blocked = 1;
    rev->ready = 0;

    if (rev->active && ngx_anytls_transport_disarm_read(ac->client) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_anytls_enable_client_read(ngx_anytls_connection_t *ac)
{
    ngx_event_t *rev;

    if (ac->client == NULL) {
        return NGX_OK;
    }

    ac->client_read_blocked = 0;
    rev = ac->client->read;

    if (ngx_anytls_transport_arm_read(ac->client) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ac->remnant_len) {
        if (!rev->ready) {
            rev->ready = 1;
        }
        ngx_post_event(rev, &ngx_posted_events);
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_anytls_input_blocked(ngx_anytls_connection_t *ac)
{
    return ac->blocked_input_streams > 0;
}


ngx_int_t
ngx_anytls_client_input_resume(ngx_anytls_connection_t *ac)
{
    size_t lowat;
    ngx_int_t rc;

    if (ac == NULL || ac->client == NULL || ac->closing) {
        return NGX_OK;
    }

    lowat = ac->conf->max_pending_input / 2;
    if (ac->pending_input > lowat) {
        return NGX_OK;
    }

    if (ngx_anytls_input_blocked(ac)) {
        return NGX_OK;
    }

    ac->input_paused = 0;

    if (ac->remnant_len) {
        size_t save = ac->remnant_len;
        ac->remnant_len = 0;
        rc = ngx_anytls_process_client_bytes(ac, ac->read_buf, save);
        if (rc != NGX_OK) {
            return rc;
        }

        if (ac->input_paused) {
            return NGX_OK;
        }
    }

    return ngx_anytls_enable_client_read(ac);
}


static void
ngx_anytls_send_http_400(ngx_anytls_connection_t *ac)
{
    static u_char body[] =
        "<html>\r\n"
        "<head><title>400 Bad Request</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>400 Bad Request</h1></center>\r\n"
        "<hr><center>nginx</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    u_char buf[512], *p;

    if (ac->client != NULL) {
        p = ngx_cpymem(buf, "HTTP/1.1 400 Bad Request" CRLF,
                       sizeof("HTTP/1.1 400 Bad Request" CRLF) - 1);
        p = ngx_cpymem(p, "Server: nginx" CRLF,
                       sizeof("Server: nginx" CRLF) - 1);
        p = ngx_cpymem(p, "Date: ", sizeof("Date: ") - 1);
        p = ngx_cpymem(p, ngx_cached_http_time.data, ngx_cached_http_time.len);
        p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);
        p = ngx_cpymem(p, "Content-Type: text/html" CRLF,
                       sizeof("Content-Type: text/html" CRLF) - 1);
        p = ngx_sprintf(p, "Content-Length: %uz" CRLF, sizeof(body) - 1);
        p = ngx_cpymem(p, "Connection: close" CRLF CRLF,
                       sizeof("Connection: close" CRLF CRLF) - 1);
        p = ngx_cpymem(p, body, sizeof(body) - 1);

        (void) ngx_anytls_transport_send(ac->client, buf, (size_t) (p - buf));
    }
}


void
ngx_anytls_client_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c, *peer;
    ngx_stream_session_t *s;
    ngx_anytls_connection_t *ac;
    u_char *buf;
    ssize_t n;
    ngx_int_t rc;

    c = rev->data;

    if (c->type == SOCK_STREAM && c->data) {
        s = c->data;
    } else {
        return;
    }

    ac = ngx_stream_get_module_ctx(s, ngx_stream_anytls_module);
    if (ac == NULL) {
        return;
    }

    if (ac->state == NGX_ANYTLS_CONN_FALLBACK) {
        peer = (c == ac->client) ? ac->fallback : ac->client;
        ngx_anytls_fallback_read(ac, c, peer);
        return;
    }

    if (ac->input_paused) {
        if (ngx_anytls_client_input_resume(ac) != NGX_OK) {
            ngx_anytls_finalize(ac);
        }
        return;
    }

    if (ac->client_read_blocked) {
        return;
    }

    buf = ac->read_buf;

    for ( ;; ) {
        n = ngx_anytls_transport_read(c, buf + ac->remnant_len, ac->read_buf_size);
        if (n == NGX_AGAIN) {
            break;
        }
        if (n == 0) {
            ac->client_eof = 1;
            ngx_anytls_finalize(ac);
            return;
        }
        if (n == NGX_ERROR) {
            ngx_anytls_finalize(ac);
            return;
        }

        if (ac->remnant_len) {
            size_t total = ac->remnant_len + (size_t) n;
            ac->remnant_len = 0;
            rc = ngx_anytls_process_client_bytes(ac, buf, total);
        } else {
            rc = ngx_anytls_process_client_bytes(ac, buf, (size_t) n);
        }
        if (rc != NGX_OK) {
            if (ac->state != NGX_ANYTLS_CONN_FALLBACK) {
                ngx_anytls_finalize(ac);
            }
            return;
        }

        if (ac->state == NGX_ANYTLS_CONN_FALLBACK) {
            return;
        }

        if (ac->client_read_blocked) {
            return;
        }
    }

    if (!ac->client_read_blocked) {
        (void) ngx_anytls_transport_arm_read(c);
    }
}


void
ngx_anytls_client_write_handler(ngx_event_t *wev)
{
    ngx_connection_t *c;
    ngx_stream_session_t *s;
    ngx_anytls_connection_t *ac;

    c = wev->data;

    if (c->data == NULL) {
        return;
    }

    s = c->data;
    ac = ngx_stream_get_module_ctx(s, ngx_stream_anytls_module);
    if (ac == NULL && c->data) {
        ac = c->data;
    }
    if (ac == NULL) {
        return;
    }

    ac->write_pending = 0;

    if (ac->state == NGX_ANYTLS_CONN_FALLBACK) {
        ngx_anytls_fallback_write(ac, c);
        return;
    }

    {
        ngx_anytls_drain_result_t dr;
        if (ngx_anytls_client_mux_drain(ac, 0, &dr) == NGX_ERROR) {
            ngx_anytls_finalize(ac);
        } else if (dr.can_finalize) {
            ngx_anytls_finalize(ac);
        }
    }
}
