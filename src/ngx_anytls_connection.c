#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_connection.h"
#include "ngx_anytls_output.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_uot.h"
#include "ngx_anytls_fallback.h"
#include "ngx_anytls_upstream_state.h"

static ngx_int_t ngx_anytls_process_auth(ngx_anytls_connection_t *ac,
    u_char *data, size_t len, size_t *consumed);
static ngx_int_t ngx_anytls_handle_psh(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_anytls_frame_t *frame);
static void ngx_anytls_fallback_read(ngx_anytls_connection_t *ac,
    ngx_connection_t *from, ngx_connection_t *to);
static void ngx_anytls_fallback_write(ngx_anytls_connection_t *ac,
    ngx_connection_t *c);

void
ngx_anytls_connection_init(ngx_stream_session_t *s,
    ngx_stream_anytls_srv_conf_t *conf)
{
    ngx_connection_t *c;
    ngx_anytls_connection_t *ac;

    c = s->connection;
    ac = ngx_pcalloc(c->pool, sizeof(ngx_anytls_connection_t));
    if (ac == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ac->session = s;
    ac->client = c;
    ac->pool = c->pool;
    ac->log = c->log;
    ac->conf = conf;
    ac->state = NGX_ANYTLS_CONN_AUTH;
    ac->peer_version = 1;
    ac->in_size = conf->buffer_size + NGX_ANYTLS_FRAME_HEADER_LEN;
    ac->in = ngx_pnalloc(c->pool, ac->in_size);
    if (ac->in == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    ac->in_pos = ac->in;
    ac->in_last = ac->in;

    ngx_rbtree_init(&ac->streams, &ac->sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&ac->stream_list);
    ngx_queue_init(&ac->ready_streams);

    ngx_stream_set_ctx(s, ac, ngx_stream_anytls_module);
    c->data = s;
    c->read->handler = ngx_anytls_client_read_handler;
    c->write->handler = ngx_anytls_client_write_handler;

    ngx_anytls_client_read_handler(c->read);
}

static ngx_int_t
ngx_anytls_process_auth(ngx_anytls_connection_t *ac, u_char *data, size_t len,
    size_t *consumed)
{
    size_t n, need;

    *consumed = 0;

    if (ac->auth_len < 34) {
        n = ngx_min(len, 34 - ac->auth_len);
        ngx_memcpy(ac->auth + ac->auth_len, data, n);
        ac->auth_len += n;
        *consumed += n;
        data += n;
        len -= n;

        if (ac->auth_len < 34) {
            return NGX_AGAIN;
        }
    }

    if (ngx_memcmp(ac->auth, ac->conf->password_hash, 32) != 0) {
        if (ngx_anytls_fallback_start(ac, ac->auth, ac->auth_len) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_DONE;
    }

    ac->auth_padding_len = (uint16_t) ((ac->auth[32] << 8) | ac->auth[33]);
    need = 34 + ac->auth_padding_len;
    if (need > sizeof(ac->auth)) {
        return NGX_ERROR;
    }

    if (ac->auth_len < need) {
        n = ngx_min(len, need - ac->auth_len);
        ngx_memcpy(ac->auth + ac->auth_len, data, n);
        ac->auth_len += n;
        *consumed += n;

        if (ac->auth_len < need) {
            return NGX_AGAIN;
        }
    }

    ac->authenticated = 1;
    ac->state = NGX_ANYTLS_CONN_SETTINGS;
    return NGX_OK;
}

ngx_int_t
ngx_anytls_process_client_bytes(ngx_anytls_connection_t *ac, u_char *data,
    size_t len)
{
    size_t consumed, used;
    ngx_int_t rc;
    ngx_anytls_frame_t frame;

    used = 0;

    if (!ac->authenticated) {
        rc = ngx_anytls_process_auth(ac, data, len, &consumed);
        data += consumed;
        len -= consumed;
        used += consumed;

        if (rc == NGX_AGAIN || rc == NGX_DONE) {
            return NGX_OK;
        }
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (len) {
        if ((size_t) (ac->in_last - ac->in) + len > ac->in_size) {
            if (ac->in_pos != ac->in) {
                ngx_memmove(ac->in, ac->in_pos,
                            (size_t) (ac->in_last - ac->in_pos));
                ac->in_last = ac->in + (ac->in_last - ac->in_pos);
                ac->in_pos = ac->in;
            }
            if ((size_t) (ac->in_last - ac->in) + len > ac->in_size) {
                return NGX_ERROR;
            }
        }
        ac->in_last = ngx_cpymem(ac->in_last, data, len);
    }

    for ( ;; ) {
        rc = ngx_anytls_parse_frame(ac->in_pos, ac->in_last, &frame, &consumed);
        if (rc == NGX_AGAIN) {
            break;
        }
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        rc = ngx_anytls_handle_frame(ac, &frame);
        if (rc != NGX_OK) {
            return rc;
        }
        ac->in_pos += consumed;
    }

    if (ac->in_pos == ac->in_last) {
        ac->in_pos = ac->in;
        ac->in_last = ac->in;
    }

    (void) used;
    return NGX_OK;
}

ngx_int_t
ngx_anytls_handle_frame(ngx_anytls_connection_t *ac, ngx_anytls_frame_t *frame)
{
    ngx_anytls_stream_t *st;
    ngx_anytls_settings_t settings;
    ngx_str_t server_settings = ngx_string("v=2\n");

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
            if (ngx_anytls_queue_frame(ac, NULL,
                                       NGX_ANYTLS_CMD_SERVER_SETTINGS, 0,
                                       server_settings.data,
                                       server_settings.len) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        if (settings.padding_md5.len != 32
            || ngx_strncmp(settings.padding_md5.data, ac->conf->padding_md5, 32)
               != 0)
        {
            if (ngx_anytls_queue_frame(ac, NULL,
                                       NGX_ANYTLS_CMD_UPDATE_PADDING, 0,
                                       ac->conf->padding_data,
                                       ac->conf->padding_data_len) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        return NGX_OK;

    case NGX_ANYTLS_CMD_HEART_REQUEST:
        return ngx_anytls_queue_frame(ac, NULL, NGX_ANYTLS_CMD_HEART_RESPONSE,
                                      frame->stream_id, NULL, 0);

    case NGX_ANYTLS_CMD_SYN:
        if (!ac->settings_received) {
            (void) ngx_anytls_queue_frame(ac, NULL, NGX_ANYTLS_CMD_ALERT, 0,
                                          (u_char *) "settings required",
                                          sizeof("settings required") - 1);
            return NGX_ERROR;
        }
        if (ngx_anytls_stream_find(ac, frame->stream_id) != NULL) {
            return NGX_OK;
        }
        st = ngx_anytls_stream_create(ac, frame->stream_id);
        return st ? NGX_OK : NGX_ERROR;

    case NGX_ANYTLS_CMD_PSH:
        st = ngx_anytls_stream_find(ac, frame->stream_id);
        if (st == NULL) {
            return NGX_OK;
        }
        return ngx_anytls_handle_psh(ac, st, frame);

    case NGX_ANYTLS_CMD_FIN:
        st = ngx_anytls_stream_find(ac, frame->stream_id);
        if (st) {
            st->in_closed = 1;
            if (st->upstream) {
                ngx_shutdown_socket(st->upstream->fd, NGX_WRITE_SHUTDOWN);
            }
            if (st->out_closed) {
                ngx_anytls_stream_close(st);
            }
        }
        return NGX_OK;

    default:
        return NGX_OK;
    }
}

static ngx_int_t
ngx_anytls_handle_psh(ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st,
    ngx_anytls_frame_t *frame)
{
    ngx_int_t rc;
    ngx_anytls_addr_t addr;
    u_char *payload;
    size_t payload_len;

    if (!st->first_psh_seen) {
        rc = ngx_anytls_parse_socksaddr(st->pool, frame->data, frame->data_len,
                                        &addr);
        if (rc != NGX_OK) {
            return rc;
        }
        st->first_psh_seen = 1;
        st->target = addr;
        payload = frame->data + addr.consumed;
        payload_len = frame->data_len - addr.consumed;

        if (addr.mode == NGX_ANYTLS_ADDR_TCP) {
            if (payload_len) {
                st->initial_data = ngx_pnalloc(st->pool, payload_len);
                if (st->initial_data == NULL) {
                    return NGX_ERROR;
                }
                ngx_memcpy(st->initial_data, payload, payload_len);
                st->initial_data_len = payload_len;
                if (ngx_anytls_upstream_queue(st, payload, payload_len)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
            return ngx_anytls_upstream_open(st, &addr);
        }

        if (ngx_anytls_uot_open(st, &addr) != NGX_OK) {
            return NGX_ERROR;
        }
        if (payload_len) {
            return ngx_anytls_uot_client_payload(st, payload, payload_len);
        }
        return NGX_OK;
    }

    if (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT) {
        return ngx_anytls_uot_client_payload(st, frame->data, frame->data_len);
    }

    return ngx_anytls_upstream_queue(st, frame->data, frame->data_len);
}

void
ngx_anytls_client_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c, *peer;
    ngx_stream_session_t *s;
    ngx_anytls_connection_t *ac;
    u_char *buf;
    ssize_t n;

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

    buf = ngx_pnalloc(ac->pool, ac->conf->buffer_size);
    if (buf == NULL) {
        ngx_anytls_finalize(ac);
        return;
    }

    for ( ;; ) {
        n = c->recv(c, buf, ac->conf->buffer_size);
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

        if (ngx_anytls_process_client_bytes(ac, buf, (size_t) n) != NGX_OK) {
            if (ac->state != NGX_ANYTLS_CONN_FALLBACK) {
                ngx_anytls_finalize(ac);
            }
            return;
        }
    }

    (void) ngx_handle_read_event(rev, 0);
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

    if (ngx_anytls_flush(ac) == NGX_ERROR) {
        ngx_anytls_finalize(ac);
    }
}

static void
ngx_anytls_fallback_write(ngx_anytls_connection_t *ac, ngx_connection_t *c)
{
    ssize_t n;
    ngx_buf_t *b;

    if (c != ac->fallback) {
        return;
    }

    b = ac->fallback_replay;
    while (b && b->pos < b->last) {
        n = c->send(c, b->pos, (size_t) (b->last - b->pos));
        if (n == NGX_AGAIN) {
            (void) ngx_handle_write_event(c->write, 0);
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_anytls_finalize(ac);
            return;
        }
        b->pos += n;
        ngx_anytls_upstream_state_add_bytes_sent(ac->session,
                                                 &ac->fallback_state, n);
    }

    ac->fallback_replay = NULL;
    if (ngx_handle_read_event(ac->client->read, 0) != NGX_OK
        || ngx_handle_read_event(ac->fallback->read, 0) != NGX_OK)
    {
        ngx_anytls_finalize(ac);
    }
}

static void
ngx_anytls_fallback_read(ngx_anytls_connection_t *ac, ngx_connection_t *from,
    ngx_connection_t *to)
{
    u_char buf[16384];
    ssize_t n, sent;

    if (to == NULL) {
        ngx_anytls_finalize(ac);
        return;
    }

    for ( ;; ) {
        n = from->recv(from, buf, sizeof(buf));
        if (n == NGX_AGAIN) {
            break;
        }
        if (n == 0 || n == NGX_ERROR) {
            ngx_anytls_finalize(ac);
            return;
        }

        sent = to->send(to, buf, (size_t) n);
        if (sent == NGX_ERROR || sent == 0) {
            ngx_anytls_finalize(ac);
            return;
        }
        if (from == ac->client && to == ac->fallback) {
            ngx_anytls_upstream_state_add_bytes_sent(ac->session,
                                                     &ac->fallback_state,
                                                     sent);
        } else if (from == ac->fallback && to == ac->client) {
            ngx_anytls_upstream_state_add_bytes_received(ac->session,
                                                         &ac->fallback_state,
                                                         sent);
        }
        if (sent == NGX_AGAIN || sent < n) {
            break;
        }
    }

    (void) ngx_handle_read_event(from->read, 0);
}

void
ngx_anytls_close_if_idle(ngx_anytls_connection_t *ac)
{
    if (ac->closing || ac->active_streams == 0) {
        ngx_anytls_finalize(ac);
    }
}

void
ngx_anytls_finalize(ngx_anytls_connection_t *ac)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;

    if (ac == NULL || ac->closing) {
        return;
    }

    ac->closing = 1;
    ngx_anytls_upstream_state_finalize(ac->session, &ac->fallback_state);

    for (q = ngx_queue_head(&ac->stream_list);
         q != ngx_queue_sentinel(&ac->stream_list);
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, link);
        ngx_anytls_stream_close(st);
    }

    if (ac->fallback) {
        ngx_close_connection(ac->fallback);
        ac->fallback = NULL;
    }

    ngx_stream_finalize_session(ac->session, NGX_STREAM_OK);
}
