#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_upstream.h"
#include "ngx_anytls_output.h"
#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream_state.h"

static ngx_int_t
ngx_anytls_test_connect(ngx_connection_t *c)
{
    int err;
    socklen_t len;

    err = 0;
    len = sizeof(err);

    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
        return NGX_ERROR;
    }

    if (err) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_anytls_upstream_block_read(ngx_anytls_stream_t *st, ngx_event_t *rev)
{
    st->upstream_read_blocked = 1;
    rev->ready = 0;

    if (rev->active && ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_anytls_upstream_open(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    ngx_int_t              rc;

    st->target = *addr;

    rc = ngx_anytls_resolve_addr(st, NGX_ANYTLS_RESOLVE_TCP, &st->target);
    if (rc == NGX_AGAIN) {
        st->state = NGX_ANYTLS_STREAM_CONNECTING;
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, st->ac->log, 0,
                      "anytls: resolve upstream target \"%V\" failed",
                      &addr->host);
        return NGX_ERROR;
    }

    return ngx_anytls_upstream_open_resolved(st);
}

ngx_int_t
ngx_anytls_upstream_open_resolved(ngx_anytls_stream_t *st)
{
    ngx_peer_connection_t *pc;
    ngx_connection_t      *c;
    ngx_int_t              rc;
    u_char                *p;

    if (!st->target.has_sockaddr) {
        return NGX_ERROR;
    }

    st->upstream_name.data = ngx_pnalloc(st->pool, NGX_SOCKADDR_STRLEN);
    if (st->upstream_name.data == NULL) {
        return NGX_ERROR;
    }
    st->upstream_name.len = ngx_sock_ntop(
        (struct sockaddr *) &st->target.sockaddr, st->target.socklen,
        st->upstream_name.data, NGX_SOCKADDR_STRLEN, 1);
    if (st->upstream_name.len == 0) {
        p = ngx_snprintf(st->upstream_name.data, NGX_SOCKADDR_STRLEN,
                         "%V:%ui", &st->target.host,
                         (ngx_uint_t) st->target.port);
        st->upstream_name.len = p - st->upstream_name.data;
    }

    pc = &st->peer;
    ngx_memzero(pc, sizeof(*pc));
    pc->sockaddr = (struct sockaddr *) &st->target.sockaddr;
    pc->socklen = st->target.socklen;
    pc->name = &st->upstream_name;
    pc->get = ngx_event_get_peer;
    pc->log = st->ac->log;
    pc->log_error = NGX_ERROR_ERR;

    if (ngx_anytls_upstream_state_open(st->ac->session, &st->upstream_state,
                                       &st->upstream_name) != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = ngx_event_connect_peer(pc);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        return NGX_ERROR;
    }

    c = pc->connection;
    c->data = st;
    c->pool = st->pool;
    c->log = st->ac->log;
    c->read->handler = ngx_anytls_upstream_read_handler;
    c->write->handler = ngx_anytls_upstream_write_handler;
    st->upstream = c;
    st->state = NGX_ANYTLS_STREAM_CONNECTING;

    if (rc == NGX_OK) {
        st->state = NGX_ANYTLS_STREAM_CONNECTED;
        st->synack_sent = 1;
        (void) ngx_anytls_queue_frame(st->ac, NULL, NGX_ANYTLS_CMD_SYNACK,
                                      st->id, NULL, 0);
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return ngx_anytls_upstream_send_pending(st);
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_anytls_upstream_queue(ngx_anytls_stream_t *st, u_char *data, size_t len)
{
    ngx_anytls_pending_t *p;

    if (len == 0) {
        return NGX_OK;
    }

    p = ngx_pcalloc(st->pool, sizeof(ngx_anytls_pending_t));
    if (p == NULL) {
        return NGX_ERROR;
    }

    p->data = ngx_pnalloc(st->pool, len);
    if (p->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p->data, data, len);
    p->len = len;

    *st->pending_in_last = p;
    st->pending_in_last = &p->next;

    if (st->upstream && st->upstream->write) {
        ngx_post_event(st->upstream->write, &ngx_posted_events);
    }

    return NGX_OK;
}

ngx_int_t
ngx_anytls_upstream_send_pending(ngx_anytls_stream_t *st)
{
    ngx_connection_t *c;
    ngx_anytls_pending_t *p;
    ssize_t n;

    c = st->upstream;
    if (c == NULL || st->state != NGX_ANYTLS_STREAM_CONNECTED) {
        return NGX_OK;
    }

    while (st->pending_in) {
        p = st->pending_in;
        n = c->send(c, p->data + p->sent, p->len - p->sent);
        if (n == NGX_ERROR || n == 0) {
            return NGX_ERROR;
        }
        if (n == NGX_AGAIN) {
            return ngx_handle_write_event(c->write, 0);
        }
        p->sent += (size_t) n;
        ngx_anytls_upstream_state_add_bytes_sent(st->ac->session,
                                                 &st->upstream_state, n);
        if (p->sent != p->len) {
            return ngx_handle_write_event(c->write, 0);
        }
        st->pending_in = p->next;
        if (st->pending_in == NULL) {
            st->pending_in_last = &st->pending_in;
        }
    }

    return NGX_OK;
}

void
ngx_anytls_upstream_write_handler(ngx_event_t *wev)
{
    ngx_connection_t *c;
    ngx_anytls_stream_t *st;

    c = wev->data;
    st = c->data;

    if (st->state == NGX_ANYTLS_STREAM_CONNECTING) {
        if (ngx_anytls_test_connect(c) != NGX_OK) {
            (void) ngx_anytls_queue_frame(st->ac, NULL, NGX_ANYTLS_CMD_SYNACK,
                                          st->id, (u_char *) "connect failed",
                                          sizeof("connect failed") - 1);
            ngx_anytls_stream_close(st);
            return;
        }
        st->state = NGX_ANYTLS_STREAM_CONNECTED;
        st->synack_sent = 1;
        (void) ngx_anytls_queue_frame(st->ac, NULL, NGX_ANYTLS_CMD_SYNACK,
                                      st->id, NULL, 0);
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_anytls_stream_close(st);
            return;
        }
    }

    if (ngx_anytls_upstream_send_pending(st) != NGX_OK) {
        ngx_anytls_stream_close(st);
    }
}

void
ngx_anytls_upstream_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c;
    ngx_anytls_stream_t *st;
    u_char *buf;
    ssize_t n;
    size_t size;
    ngx_int_t rc;

    c = rev->data;
    st = c->data;
    size = st->ac->conf->buffer_size;
    if (size > NGX_ANYTLS_MAX_FRAME_DATA) {
        size = NGX_ANYTLS_MAX_FRAME_DATA;
    }
    if (st->read_buf == NULL || st->read_buf_size < size) {
        st->read_buf = ngx_pnalloc(st->pool, size);
        if (st->read_buf == NULL) {
            ngx_anytls_stream_close(st);
            return;
        }
        st->read_buf_size = size;
    }
    buf = st->read_buf;

    for ( ;; ) {
        if (!ngx_anytls_output_has_room(st->ac, size)) {
            if (ngx_anytls_upstream_block_read(st, rev) != NGX_OK) {
                ngx_anytls_stream_close(st);
            }
            return;
        }

        n = c->recv(c, buf, size);
        if (n == NGX_AGAIN) {
            break;
        }
        if (n == 0) {
            st->out_closed = 1;
            (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_FIN,
                                          st->id, NULL, 0);
            ngx_close_connection(c);
            st->upstream = NULL;
            if (st->in_closed) {
                ngx_anytls_stream_close(st);
            }
            return;
        }
        if (n == NGX_ERROR) {
            ngx_anytls_stream_close(st);
            return;
        }

        rc = ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_PSH, st->id,
                                    buf, (size_t) n);
        if (rc == NGX_AGAIN) {
            if (ngx_anytls_upstream_block_read(st, rev) != NGX_OK) {
                ngx_anytls_stream_close(st);
            }
            return;
        }
        if (rc != NGX_OK) {
            ngx_anytls_stream_close(st);
            return;
        }

        ngx_anytls_upstream_state_add_bytes_received(st->ac->session,
                                                     &st->upstream_state, n);
    }

    (void) ngx_handle_read_event(rev, 0);
}
