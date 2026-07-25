#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_upstream.h"
#include "ngx_anytls_connection.h"
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


void
ngx_anytls_upstream_discard_pending(ngx_anytls_stream_t *st)
{
    ngx_anytls_pending_t *p, *n;

    p = st->pending_in;
    while (p) {
        n = p->next;
        if (p->data) {
            ngx_free(p->data);
        }
        p = n;
    }

    if (st->ac->pending_input >= st->pending_in_bytes) {
        st->ac->pending_input -= st->pending_in_bytes;
    } else {
        st->ac->pending_input = 0;
    }

    st->pending_in = NULL;
    st->pending_in_last = &st->pending_in;
    st->pending_in_bytes = 0;

    (void) ngx_anytls_resume_input(st->ac);
}


static void
ngx_anytls_upstream_free_pending(ngx_anytls_stream_t *st,
    ngx_anytls_pending_t *p)
{
    if (p->data) {
        ngx_free(p->data);
    }

    p->data = NULL;
    p->len = 0;
    p->sent = 0;

    if (st->free_pending_in_count < NGX_ANYTLS_MAX_FREE_PENDING_IN) {
        p->next = st->free_pending_in;
        st->free_pending_in = p;
        st->free_pending_in_count++;
    }
}


ngx_chain_t *
ngx_anytls_upstream_get_read_buf(ngx_anytls_stream_t *st, size_t size)
{
    ngx_chain_t *cl;
    ngx_buf_t   *b;

    cl = st->free_read_bufs;
    if (cl) {
        st->free_read_bufs = cl->next;
        st->free_read_bufs_count--;
        cl->next = NULL;

        b = cl->buf;
        if ((size_t) (b->end - b->start) >= size) {
            b->pos = b->start;
            b->last = b->start;
            return cl;
        }
    } else {
        cl = ngx_alloc_chain_link(st->pool);
        if (cl == NULL) {
            return NULL;
        }
        b = ngx_calloc_buf(st->pool);
        if (b == NULL) {
            return NULL;
        }
        cl->buf = b;
        cl->next = NULL;
    }

    b = cl->buf;
    b->start = ngx_pnalloc(st->pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->start + size;
    b->temporary = 1;

    return cl;
}


void
ngx_anytls_upstream_free_read_buf(ngx_anytls_stream_t *st, ngx_chain_t *cl)
{
    if (st == NULL || cl == NULL || st->state == NGX_ANYTLS_STREAM_CLOSED) {
        return;
    }

    if (st->free_read_bufs_count < NGX_ANYTLS_MAX_FREE_READ_BUFS) {
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;
        cl->next = st->free_read_bufs;
        st->free_read_bufs = cl;
        st->free_read_bufs_count++;
    }
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
        (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_SYNACK,
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
    ngx_connection_t *c;
    ssize_t n;

    if (len == 0) {
        return NGX_OK;
    }

    c = st->upstream;
    if (c && st->state == NGX_ANYTLS_STREAM_CONNECTED
        && st->pending_in == NULL)
    {
        while (len) {
            n = c->send(c, data, len);
            if (n == NGX_ERROR || n == 0) {
                return NGX_ERROR;
            }
            if (n == NGX_AGAIN) {
                break;
            }

            data += n;
            len -= (size_t) n;
            ngx_anytls_upstream_state_add_bytes_sent(st->ac->session,
                                                     &st->upstream_state, n);
        }

        if (len == 0) {
            return NGX_OK;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    p = st->free_pending_in;
    if (p) {
        st->free_pending_in = p->next;
        st->free_pending_in_count--;
        ngx_memzero(p, sizeof(ngx_anytls_pending_t));
    } else {
        p = ngx_pcalloc(st->pool, sizeof(ngx_anytls_pending_t));
    }
    if (p == NULL) {
        return NGX_ERROR;
    }

    p->data = ngx_alloc(len, st->ac->log);
    if (p->data == NULL) {
        p->next = st->free_pending_in;
        st->free_pending_in = p;
        return NGX_ERROR;
    }

    ngx_memcpy(p->data, data, len);
    p->len = len;

    *st->pending_in_last = p;
    st->pending_in_last = &p->next;
    st->pending_in_bytes += len;
    st->ac->pending_input += len;

    if (st->upstream && st->upstream->write) {
        ngx_post_event(st->upstream->write, &ngx_posted_events);
    }

    if (st->pending_in_bytes > st->ac->conf->max_pending_input) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, st->ac->log, 0,
                       "anytls: stream %ui input queue reached %uz bytes, "
                       "pausing input", (ngx_uint_t) st->id,
                       st->ac->conf->max_pending_input);

        if (ngx_anytls_pause_input(st->ac) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    if (st->ac->pending_input > st->ac->conf->max_pending_input) {
        if (ngx_anytls_pause_input(st->ac) != NGX_OK) {
            return NGX_ERROR;
        }
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
        if (st->pending_in_bytes >= p->len) {
            st->pending_in_bytes -= p->len;
        } else {
            st->pending_in_bytes = 0;
        }
        if (st->ac->pending_input >= p->len) {
            st->ac->pending_input -= p->len;
        } else {
            st->ac->pending_input = 0;
        }
        if (st->pending_in == NULL) {
            st->pending_in_last = &st->pending_in;
        }
        ngx_anytls_upstream_free_pending(st, p);
    }

    return ngx_anytls_resume_input(st->ac);
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
            (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_SYNACK,
                                          st->id, (u_char *) "connect failed",
                                          sizeof("connect failed") - 1);
            ngx_anytls_stream_close(st);
            return;
        }
        st->state = NGX_ANYTLS_STREAM_CONNECTED;
        st->synack_sent = 1;
        (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_SYNACK,
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
    ngx_chain_t *cl;
    ngx_buf_t *b;
    ssize_t n;
    size_t size;
    ngx_int_t rc;

    c = rev->data;
    st = c->data;
    size = st->ac->conf->buffer_size;
    if (size > NGX_ANYTLS_MAX_FRAME_DATA) {
        size = NGX_ANYTLS_MAX_FRAME_DATA;
    }
    for ( ;; ) {
        if (!ngx_anytls_output_has_room(st->ac, size)) {
            if (ngx_anytls_upstream_block_read(st, rev) != NGX_OK) {
                ngx_anytls_stream_close(st);
            }
            return;
        }

        cl = ngx_anytls_upstream_get_read_buf(st, size);
        if (cl == NULL) {
            ngx_anytls_stream_close(st);
            return;
        }
        b = cl->buf;

        n = c->recv(c, b->last, size);
        if (n == NGX_AGAIN) {
            ngx_anytls_upstream_free_read_buf(st, cl);
            break;
        }
        if (n == 0) {
            ngx_anytls_upstream_free_read_buf(st, cl);
            if (!st->fin_queued) {
                (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_FIN,
                                              st->id, NULL, 0);
            }
            ngx_close_connection(c);
            st->upstream = NULL;
            if (st->in_closed) {
                ngx_anytls_stream_close(st);
            }
            return;
        }
        if (n == NGX_ERROR) {
            ngx_anytls_upstream_free_read_buf(st, cl);
            ngx_anytls_stream_close(st);
            return;
        }

        b->last += n;
        rc = ngx_anytls_queue_chain_frame(st->ac, st, NGX_ANYTLS_CMD_PSH,
                                          st->id, cl, (size_t) n, 1);
        if (rc == NGX_AGAIN) {
            ngx_anytls_upstream_free_read_buf(st, cl);
            if (ngx_anytls_upstream_block_read(st, rev) != NGX_OK) {
                ngx_anytls_stream_close(st);
            }
            return;
        }
        if (rc != NGX_OK) {
            ngx_anytls_upstream_free_read_buf(st, cl);
            ngx_anytls_stream_close(st);
            return;
        }

        ngx_anytls_upstream_state_add_bytes_received(st->ac->session,
                                                     &st->upstream_state, n);
    }

    (void) ngx_handle_read_event(rev, 0);
}
