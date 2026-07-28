#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_core.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_output.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_connection.h"
#include "ngx_anytls_upstream_state.h"


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
ngx_anytls_upstream_block_read(ngx_anytls_stream_t *st, ngx_event_t *rev)
{
    if (st->upstream_read_blocked) {
        return NGX_OK;
    }
    st->upstream_read_blocked = 1;
    st->blocked_by_upstream = 1;
    rev->ready = 0;

    ngx_queue_insert_tail(&st->ac->blocked_upstream_reads, &st->upstream_block);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, st->ac->log, 0,
                   "anytls: upstream block st=%ui pend_out=%uz",
                   (ngx_uint_t) st->id, st->pending_out);

    if (rev->active) {
        ngx_connection_t *blk_c;
        blk_c = rev->data;
        if (ngx_anytls_transport_disarm_read(blk_c) != NGX_OK) {
            return NGX_ERROR;
        }
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
                n = ngx_anytls_transport_read(c, b->last + 2, size - 2);
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
                n = ngx_anytls_transport_read(c, b->last, size);
                if (n == NGX_AGAIN) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    break;
                }
                if (n == 0) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    ngx_anytls_transport_close(c);
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
            st->last_activity = ngx_current_msec;
            frames++;
        }

        (void) ngx_anytls_transport_arm_read(c);
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
        } else {
            st->last_activity = ngx_current_msec;
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
