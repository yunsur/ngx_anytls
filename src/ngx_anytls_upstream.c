#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_upstream.h"
#include "ngx_anytls_connection.h"
#include "ngx_anytls_output.h"
#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream_state.h"

static void *ngx_anytls_upstream_alloc_pending_buf(ngx_anytls_connection_t *ac,
    size_t len);
static void ngx_anytls_upstream_free_pending_buf(ngx_anytls_connection_t *ac,
    void *buf);


ngx_int_t
ngx_anytls_upstream_mux_init(ngx_anytls_connection_t *ac)
{
    ngx_queue_init(&ac->upstream_mux.read_ready);
    ngx_queue_init(&ac->upstream_mux.write_ready);
    ngx_queue_init(&ac->upstream_mux.connect_pending);
    return NGX_OK;
}


void
ngx_anytls_upstream_mux_destroy(ngx_anytls_connection_t *ac)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;

    for (q = ngx_queue_head(&ac->upstream_mux.read_ready);
         q != ngx_queue_sentinel(&ac->upstream_mux.read_ready); q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_read_queue);
        st->upstream_read_ready = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);
    }

    for (q = ngx_queue_head(&ac->upstream_mux.write_ready);
         q != ngx_queue_sentinel(&ac->upstream_mux.write_ready); q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_write_queue);
        st->upstream_write_ready = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);
    }

    for (q = ngx_queue_head(&ac->upstream_mux.connect_pending);
         q != ngx_queue_sentinel(&ac->upstream_mux.connect_pending); q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, connect_queue);
        st->connect_pending = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);
    }
}

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
    if (st->upstream_read_blocked) {
        return NGX_OK;
    }
    st->upstream_read_blocked = 1;
    st->blocked_by_upstream = 1;
    rev->ready = 0;

    ngx_queue_insert_tail(&st->ac->blocked_upstream_reads, &st->upstream_block);

    if (rev->active && ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_anytls_upstream_mux_drain_reads(ngx_anytls_connection_t *ac,
    ngx_uint_t budget)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;
    ngx_connection_t *c;
    ngx_chain_t *cl;
    ngx_buf_t *b;
    ssize_t n;
    size_t size;
    ngx_int_t rc;
    ngx_uint_t frames;

    frames = 0;

    for (q = ngx_queue_head(&ac->upstream_mux.read_ready);
         q != ngx_queue_sentinel(&ac->upstream_mux.read_ready)
         && frames < budget;
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_read_queue);

        st->upstream_read_ready = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);

        if ((st->upstream_type != NGX_ANYTLS_UPSTREAM_UOT
                 && st->upstream == NULL)
            || (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT
                 && st->udp == NULL)
            || (st->state != NGX_ANYTLS_STREAM_CONNECTED
                && st->state != NGX_ANYTLS_STREAM_HALF_CLOSED))
        {
            continue;
        }

        c = (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT) ? st->udp : st->upstream;
        size = ac->conf->buffer_size;
        if (size > NGX_ANYTLS_MAX_FRAME_DATA) {
            size = NGX_ANYTLS_MAX_FRAME_DATA;
        }

        for ( ;; ) {
            if (frames >= budget) {
                /* Budget exhausted — re-queue stream for next round */
                if (!st->upstream_read_ready && !st->upstream_read_blocked) {
                    st->upstream_read_ready = 1;
                    ngx_queue_insert_tail(&ac->upstream_mux.read_ready,
                                          &st->upstream_read_queue);
                }
                break;
            }

            if (ac->output_pressure || !ngx_anytls_output_has_room(ac, size)) {
                if (ngx_anytls_upstream_block_read(st, c->read) != NGX_OK) {
                    ngx_anytls_stream_close(st);
                }
                goto next_stream;
            }

            cl = ngx_anytls_upstream_get_read_buf(ac, size);
            if (cl == NULL) {
                ngx_anytls_stream_close(st);
                goto next_stream;
            }
            b = cl->buf;

            if (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT
                && st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT)
            {
                /* Connected UDP: read datagram with 2-byte length prefix.
                 * Buffer has size + NGX_ANYTLS_FRAME_HEADER_LEN capacity.
                 * recv at most size - 2, then write 2-byte header at b->last.
                 * Guard size <= 2 to avoid unsigned underflow. */
                if (size <= 2) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    ngx_anytls_stream_close(st);
                    goto next_stream;
                }
                n = c->recv(c, b->last + 2, size - 2);
                if (n == NGX_AGAIN) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    break;
                }
                if (n == NGX_ERROR) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    ngx_anytls_stream_close(st);
                    goto next_stream;
                }
                if (n == 0) {
                    b->last[0] = 0;
                    b->last[1] = 0;
                    n = 2;
                } else {
                    b->last[0] = (u_char) ((size_t) n >> 8);
                    b->last[1] = (u_char) n;
                    b->last += 2;
                    b->last += n;
                    n += 2;
                }
            } else {
                n = c->recv(c, b->last, size);
                if (n == NGX_AGAIN) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    break;
                }
                if (n == 0) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    ngx_close_connection(c);
                    st->upstream = NULL;

                    (void) ngx_anytls_stream_send_fin_and_close(st);
                    goto next_stream;
                }
                if (n == NGX_ERROR) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    ngx_anytls_stream_close(st);
                    goto next_stream;
                }

                b->last += n;
            }

            rc = ngx_anytls_queue_chain_frame(ac, st, NGX_ANYTLS_CMD_PSH,
                                              st->id, cl, (size_t) n, 1);
            if (rc == NGX_AGAIN) {
                ngx_anytls_upstream_free_read_buf(ac, cl);
                if (ngx_anytls_upstream_block_read(st, c->read) != NGX_OK) {
                    ngx_anytls_stream_close(st);
                }
                goto next_stream;
            }
            if (rc != NGX_OK) {
                ngx_anytls_upstream_free_read_buf(ac, cl);
                ngx_anytls_stream_close(st);
                goto next_stream;
            }

            ngx_anytls_upstream_state_add_bytes_received(ac->session,
                                                         &st->upstream_state, n);
            frames++;
        }

        (void) ngx_handle_read_event(c->read, 0);
    next_stream:
        ;
    }

    return NGX_OK;
}


ngx_int_t
ngx_anytls_upstream_mux_drain_writes(ngx_anytls_connection_t *ac,
    ngx_uint_t budget)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;
    ngx_uint_t count;

    count = 0;

    for (q = ngx_queue_head(&ac->upstream_mux.write_ready);
         q != ngx_queue_sentinel(&ac->upstream_mux.write_ready)
         && count < budget;
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_write_queue);

        st->upstream_write_ready = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);

        if (ngx_anytls_upstream_send_pending(st) == NGX_ERROR) {
            ngx_anytls_stream_close(st);
        }

        count++;
    }

    return NGX_OK;
}


void
ngx_anytls_upstream_mux_suspend_reads(ngx_anytls_connection_t *ac)
{
    ngx_queue_t *q;
    ngx_anytls_stream_t *st;
    ngx_connection_t *c;

    ac->output_pressure = 1;

    /* Move all read_ready streams to blocked_upstream_reads */

    while (!ngx_queue_empty(&ac->upstream_mux.read_ready)) {
        q = ngx_queue_head(&ac->upstream_mux.read_ready);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_read_queue);

        st->upstream_read_ready = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);

        /* Skip stale streams that were closed between queue and suspend */
        c = (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT)
                ? st->udp : st->upstream;
        if (c == NULL || c->read == NULL
            || st->state == NGX_ANYTLS_STREAM_CLOSED
            || st->state == NGX_ANYTLS_STREAM_CLOSING)
        {
            continue;
        }

        ngx_anytls_upstream_block_read(st, c->read);
    }
}


void
ngx_anytls_upstream_mux_resume_reads(ngx_anytls_connection_t *ac)
{
    ac->output_pressure = 0;

    /* Actually re-arm blocked upstream reads */
    ngx_anytls_resume_upstream_reads(ac);
}


void
ngx_anytls_upstream_mux_stream_output_drained(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    /* Called when a stream's pending output has been drained (sent to client).
     * If this stream was blocked on output, re-enable upstream reads.
     * The global resume path handles this; per-stream resume is
     * a future optimization. */
    if (st->upstream_read_blocked) {
        /* Let the global resume mechanism pick this stream up */
        ngx_anytls_resume_upstream_reads(ac);
    }
}


ngx_int_t
ngx_anytls_upstream_mux_open(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    /* Delegates to ngx_anytls_upstream_open() which handles DNS and socket
     * connect.  socket connect pending is tracked via st->connect_pending +
     * st->connect_queue (set in open_resolved async path, cleared by
     * on_connect_ready or stream_close).  DNS resolution pending is tracked
     * separately via st->resolver_pending / st->resolver_ctx. */
    return ngx_anytls_upstream_open(st, addr);
}


void
ngx_anytls_upstream_mux_on_connect_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (st->connect_pending) {
        st->connect_pending = 0;
        ngx_queue_remove(&st->connect_queue);
        ngx_queue_init(&st->connect_queue);
    }
}


void
ngx_anytls_upstream_mux_on_read_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    ngx_connection_t *c;

    c = (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT)
            ? st->udp : st->upstream;
    if (c == NULL
        || (st->state != NGX_ANYTLS_STREAM_CONNECTED
            && st->state != NGX_ANYTLS_STREAM_HALF_CLOSED))
    {
        return;
    }

    if (!st->upstream_read_ready && !st->upstream_read_blocked) {
        st->upstream_read_ready = 1;
        ngx_queue_insert_tail(&ac->upstream_mux.read_ready,
                              &st->upstream_read_queue);
    }

    (void) ngx_anytls_upstream_mux_drain_reads(ac, 32);
}


void
ngx_anytls_upstream_mux_on_write_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (st->upstream == NULL
        || (st->state != NGX_ANYTLS_STREAM_CONNECTED
            && st->state != NGX_ANYTLS_STREAM_HALF_CLOSED
            && st->state != NGX_ANYTLS_STREAM_CONNECTING))
    {
        return;
    }

    if (!st->upstream_write_ready) {
        st->upstream_write_ready = 1;
        ngx_queue_insert_tail(&ac->upstream_mux.write_ready,
                              &st->upstream_write_queue);
    }

    (void) ngx_anytls_upstream_mux_drain_writes(ac, 32);
}


void
ngx_anytls_upstream_mux_close_stream(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t reason)
{
    if (st == NULL || st->state == NGX_ANYTLS_STREAM_CLOSED) {
        return;
    }

    if (reason != 0) {
        u_char code = (u_char) reason;
        if (ngx_anytls_queue_frame(ac, st, NGX_ANYTLS_CMD_ALERT,
                                   st->id, &code, 1) != NGX_OK)
        {
            /* Alert frame dropped; still proceed with close */
        }
    }

    ngx_anytls_stream_send_fin_and_close(st);
}


static ngx_int_t
ngx_anytls_upstream_block_input(ngx_anytls_stream_t *st)
{
    if (!st->input_blocked) {
        st->input_blocked = 1;
        st->input_exhausted = 1;
        st->ac->blocked_input_streams++;

        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, st->ac->log, 0,
                       "anytls: stream %ui input blocked, pending:%uz "
                       "limit:%uz", (ngx_uint_t) st->id,
                       st->pending_in_bytes,
                       st->ac->conf->max_pending_input);
    }

    return ngx_anytls_pause_input(st->ac);
}


static ngx_int_t
ngx_anytls_upstream_update_input_state(ngx_anytls_stream_t *st)
{
    size_t lowat;

    if (!st->input_blocked) {
        return NGX_OK;
    }

    lowat = st->ac->conf->max_pending_input / 2;
    if (st->pending_in_bytes > lowat) {
        return NGX_OK;
    }

    st->input_blocked = 0;
    st->input_exhausted = 0;
    if (st->ac->blocked_input_streams) {
        st->ac->blocked_input_streams--;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, st->ac->log, 0,
                   "anytls: stream %ui input unblocked, pending:%uz "
                   "lowat:%uz", (ngx_uint_t) st->id, st->pending_in_bytes,
                   lowat);

    return ngx_anytls_resume_input(st->ac);
}


void
ngx_anytls_upstream_discard_pending(ngx_anytls_stream_t *st)
{
    ngx_anytls_pending_t *p, *n;

    p = st->pending_in;
    while (p) {
        n = p->next;
        if (p->data) {
            ngx_anytls_upstream_free_pending_buf(st->ac, p->data);
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
    if (st->input_blocked) {
        st->input_blocked = 0;
        st->input_exhausted = 0;
        if (st->ac->blocked_input_streams) {
            st->ac->blocked_input_streams--;
        }
    }

    (void) ngx_anytls_resume_input(st->ac);
}


static void
ngx_anytls_upstream_free_pending(ngx_anytls_stream_t *st,
    ngx_anytls_pending_t *p)
{
    if (p->data) {
        ngx_anytls_upstream_free_pending_buf(st->ac, p->data);
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


typedef struct {
    void  *next;
    size_t cap;
} ngx_anytls_pending_buf_hdr_t;


static void *
ngx_anytls_upstream_alloc_pending_buf(ngx_anytls_connection_t *ac, size_t len)
{
    ngx_anytls_pending_buf_hdr_t *hdr, *prev;

    prev = NULL;
    hdr = ac->free_pending_bufs;
    while (hdr) {
        if (hdr->cap >= len) {
            if (prev) {
                prev->next = hdr->next;
            } else {
                ac->free_pending_bufs = hdr->next;
            }
            ac->free_pending_bufs_count--;
            return hdr + 1;
        }
        prev = hdr;
        hdr = hdr->next;
    }

    hdr = ngx_alloc(sizeof(ngx_anytls_pending_buf_hdr_t) + len, ac->log);
    if (hdr == NULL) {
        return NULL;
    }
    hdr->cap = len;
    return hdr + 1;
}


static void
ngx_anytls_upstream_free_pending_buf(ngx_anytls_connection_t *ac, void *data)
{
    ngx_anytls_pending_buf_hdr_t *hdr;

    hdr = (ngx_anytls_pending_buf_hdr_t *) data - 1;
    if (ac->free_pending_bufs_count < NGX_ANYTLS_MAX_FREE_PENDING_IN) {
        hdr->next = ac->free_pending_bufs;
        ac->free_pending_bufs = hdr;
        ac->free_pending_bufs_count++;
    } else {
        ngx_free(hdr);
    }
}


ngx_chain_t *
ngx_anytls_upstream_get_read_buf(ngx_anytls_connection_t *ac, size_t size)
{
    ngx_chain_t *cl, **ll;
    ngx_buf_t   *b;
    size_t       capacity;

    capacity = size + NGX_ANYTLS_FRAME_HEADER_LEN;

    for (ll = &ac->free_read_bufs; *ll; ll = &(*ll)->next) {
        cl = *ll;
        b = cl->buf;

        if ((size_t) (b->end - b->start) >= capacity) {
            *ll = cl->next;
            ac->free_read_bufs_count--;
            cl->next = NULL;
            b->pos = b->start + NGX_ANYTLS_FRAME_HEADER_LEN;
            b->last = b->pos;
            return cl;
        }
    }

    cl = ngx_alloc(sizeof(ngx_chain_t), ac->log);
    if (cl == NULL) {
        return NULL;
    }

    b = ngx_alloc(sizeof(ngx_buf_t), ac->log);
    if (b == NULL) {
        ngx_free(cl);
        return NULL;
    }

    ngx_memzero(b, sizeof(ngx_buf_t));
    cl->buf = b;
    cl->next = NULL;

    b->start = ngx_alloc(capacity, ac->log);
    if (b->start == NULL) {
        ngx_free(b);
        ngx_free(cl);
        return NULL;
    }

    b->pos = b->start + NGX_ANYTLS_FRAME_HEADER_LEN;
    b->last = b->pos;
    b->end = b->start + capacity;
    b->temporary = 1;

    return cl;
}


void
ngx_anytls_upstream_free_read_buf(ngx_anytls_connection_t *ac, ngx_chain_t *cl)
{
    if (ac == NULL || cl == NULL) {
        return;
    }

    if (ac->free_read_bufs_count < NGX_ANYTLS_MAX_FREE_READ_BUFS) {
        cl->buf->pos = cl->buf->start + NGX_ANYTLS_FRAME_HEADER_LEN;
        cl->buf->last = cl->buf->pos;
        cl->next = ac->free_read_bufs;
        ac->free_read_bufs = cl;
        ac->free_read_bufs_count++;

    } else {
        ngx_free(cl->buf->start);
        ngx_free(cl->buf);
        ngx_free(cl);
    }
}


ngx_int_t
ngx_anytls_upstream_open(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    ngx_int_t              rc;

    ngx_anytls_addr_copy(&st->target, addr);

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

    ngx_pool_t *pool;
    pool = ngx_anytls_stream_pool(st);
    if (pool == NULL) { return NGX_ERROR; }
    st->upstream_name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
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
    if (ngx_anytls_stream_pool(st) == NULL) {
        return NGX_ERROR;
    }
    c->pool = st->pool;
    c->log = st->ac->log;
    c->read->handler = ngx_anytls_upstream_read_handler;
    c->write->handler = ngx_anytls_upstream_write_handler;
    st->upstream = c;
    st->state = NGX_ANYTLS_STREAM_CONNECTING;

    if (rc == NGX_OK) {
        st->state = NGX_ANYTLS_STREAM_CONNECTED;
        (void) ngx_anytls_send_synack(st, NULL, 0);
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return ngx_anytls_upstream_send_pending(st);
    }

    st->connect_pending = 1;
    ngx_queue_insert_tail(&st->ac->upstream_mux.connect_pending,
                          &st->connect_queue);

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
        ngx_pool_t *pool;
        pool = ngx_anytls_stream_pool(st);
        if (pool == NULL) { return NGX_ERROR; }
        p = ngx_pcalloc(pool, sizeof(ngx_anytls_pending_t));
    }
    if (p == NULL) {
        return NGX_ERROR;
    }

    p->data = ngx_anytls_upstream_alloc_pending_buf(st->ac, len);
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
        return ngx_anytls_upstream_block_input(st);
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
    if (c == NULL
        || (st->state != NGX_ANYTLS_STREAM_CONNECTED
            && st->state != NGX_ANYTLS_STREAM_HALF_CLOSED))
    {
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

        if (ngx_anytls_upstream_update_input_state(st) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    /* If client FIN arrived while data was still pending, the FIN handler
     * deferred half-close. Now that all data is flushed, do it. */
    if (st->pending_shutdown && st->upstream) {
        st->pending_shutdown = 0;
        ngx_shutdown_socket(st->upstream->fd, NGX_WRITE_SHUTDOWN);
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
            (void) ngx_anytls_send_synack(st, (u_char *) "connect failed",
                                          sizeof("connect failed") - 1);
            ngx_anytls_stream_close(st);
            return;
        }
        ngx_anytls_upstream_mux_on_connect_ready(st->ac, st);
        st->state = NGX_ANYTLS_STREAM_CONNECTED;
        (void) ngx_anytls_send_synack(st, NULL, 0);
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_anytls_stream_close(st);
            return;
        }
    }

    ngx_anytls_upstream_mux_on_write_ready(st->ac, st);
}

void
ngx_anytls_upstream_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c;
    ngx_anytls_stream_t *st;

    c = rev->data;
    st = c->data;

    ngx_anytls_upstream_mux_on_read_ready(st->ac, st);

    /* Re-arm read event if stream still active */
    if (st->upstream && !st->upstream_read_blocked
        && !st->closing
        && st->state != NGX_ANYTLS_STREAM_CLOSED)
    {
        (void) ngx_handle_read_event(rev, 0);
    }
}
