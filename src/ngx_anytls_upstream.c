#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_upstream.h"
#include "ngx_anytls_output.h"
#include "ngx_anytls_stream.h"

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

ngx_int_t
ngx_anytls_upstream_open(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    ngx_url_t              url;
    ngx_peer_connection_t *pc;
    ngx_connection_t      *c;
    ngx_int_t              rc;

    if (ngx_anytls_addr_to_url(st->pool, addr, &url) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, st->ac->log, 0,
                      "anytls: invalid upstream target \"%V\"", &addr->host);
        return NGX_ERROR;
    }

    pc = &st->peer;
    ngx_memzero(pc, sizeof(*pc));
    pc->sockaddr = url.addrs[0].sockaddr;
    pc->socklen = url.addrs[0].socklen;
    pc->name = &url.addrs[0].name;
    st->upstream_name = url.addrs[0].name;
    pc->get = ngx_event_get_peer;
    pc->log = st->ac->log;
    pc->log_error = NGX_ERROR_ERR;

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

    c = rev->data;
    st = c->data;
    size = st->ac->conf->buffer_size;
    buf = ngx_pnalloc(st->pool, size);
    if (buf == NULL) {
        ngx_anytls_stream_close(st);
        return;
    }

    for ( ;; ) {
        n = c->recv(c, buf, size);
        if (n == NGX_AGAIN) {
            break;
        }
        if (n == 0) {
            st->out_closed = 1;
            (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_FIN,
                                          st->id, NULL, 0);
            ngx_anytls_stream_close(st);
            return;
        }
        if (n == NGX_ERROR) {
            ngx_anytls_stream_close(st);
            return;
        }

        if (ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_PSH, st->id,
                                   buf, (size_t) n) != NGX_OK)
        {
            break;
        }
    }

    (void) ngx_handle_read_event(rev, 0);
}
