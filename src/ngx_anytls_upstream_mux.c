#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_core.h"
#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_connection.h"
#include "ngx_anytls_upstream_state.h"
#include "ngx_anytls_uot.h"
#include "ngx_anytls_private.h"


/* Per-cycle scheduling budget (internal to upstream mux).
 * on_read_ready / on_write_ready initialise one of these and pass
 * it to the corresponding static drain function. */
typedef struct {
    ngx_uint_t   frame_budget;
    size_t       byte_budget;
    ngx_uint_t   stream_budget;

    ngx_uint_t   processed_frames;
    size_t       processed_bytes;
    ngx_uint_t   visited_streams;
} ngx_anytls_schedule_budget_t;


static ngx_uint_t ngx_anytls_upstream_mux_process_blocked(
    ngx_anytls_connection_t *ac);

static ngx_int_t ngx_anytls_upstream_mux_drain_reads(
    ngx_anytls_connection_t *ac, ngx_anytls_schedule_budget_t *sched);
static ngx_int_t ngx_anytls_upstream_mux_drain_writes(
    ngx_anytls_connection_t *ac, ngx_anytls_schedule_budget_t *sched);


ngx_uint_t
ngx_anytls_upstream_mux_is_uot(ngx_anytls_stream_t *st)
{
    return (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT) ? 1 : 0;
}


void
ngx_anytls_upstream_mux_handle_client_fin(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    /* Mark stream as closed-by-protocol first so downstream code
     * sees consistent state. */
    ngx_anytls_core_stream_mark_closed(st);

    if (ngx_anytls_upstream_mux_is_uot(st)) {
        ngx_anytls_uot_close(st);
        ngx_anytls_core_stream_close(st);
        return;
    }

    /* TCP: flush pending data then half-close */
    if (st->upstream && st->state == NGX_ANYTLS_STREAM_CONNECTED) {
        ngx_int_t rc;

        rc = ngx_anytls_upstream_send_pending(st,
                                NGX_ANYTLS_UPSTREAM_SEND_UNLIMITED, NULL);
        if (rc == NGX_ERROR) {
            ngx_anytls_core_stream_close(st);
        } else if (st->pending_in == NULL) {
            ngx_anytls_transport_shutdown_write(st->upstream);
            st->state = NGX_ANYTLS_STREAM_HALF_CLOSED;
        } else {
            st->state = NGX_ANYTLS_STREAM_HALF_CLOSED;
            st->pending_shutdown = 1;
        }
        return;
    }

    /* No upstream or still connecting */
    ngx_anytls_core_stream_close(st);
}


ngx_int_t
ngx_anytls_upstream_mux_handle_client_payload(ngx_anytls_stream_t *st,
    u_char *data, size_t len)
{
    if (ngx_anytls_upstream_mux_is_uot(st)) {
        return ngx_anytls_uot_client_payload(st, data, len);
    }

    return ngx_anytls_upstream_queue(st, data, len);
}


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


static ngx_inline ngx_connection_t *
ngx_anytls_upstream_mux_read_conn(ngx_anytls_stream_t *st)
{
    return (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT)
            ? st->udp : st->upstream;
}


/* Write connection — the TCP or connected-UoT stream socket. */
static ngx_inline ngx_connection_t *
ngx_anytls_upstream_mux_write_conn(ngx_anytls_stream_t *st)
{
    return st->upstream;
}


/* Close the upstream endpoint (TCP or UoT) and clear the pointer. */
static void
ngx_anytls_upstream_mux_close_endpoint(ngx_anytls_stream_t *st)
{
    if (st->upstream) {
        ngx_anytls_transport_close(st->upstream);
        st->upstream = NULL;
    }
    if (st->udp) {
        ngx_anytls_uot_close(st);
    }
}


/* Query: is upstream read currently blocked by output pressure? */
static ngx_inline ngx_uint_t
ngx_anytls_upstream_mux_read_blocked(ngx_anytls_stream_t *st)
{
    return st->upstream_read_blocked ? 1 : 0;
}


static ngx_inline ngx_int_t
ngx_anytls_upstream_mux_stream_readable(ngx_anytls_stream_t *st)
{
    ngx_connection_t *c;

    c = ngx_anytls_upstream_mux_read_conn(st);
    if (c == NULL) {
        return 0;
    }

    return (st->state == NGX_ANYTLS_STREAM_CONNECTED
            || st->state == NGX_ANYTLS_STREAM_HALF_CLOSED) ? 1 : 0;
}


static ngx_inline ngx_int_t
ngx_anytls_upstream_mux_stream_writable(ngx_anytls_stream_t *st)
{
    if (ngx_anytls_upstream_mux_write_conn(st) == NULL) {
        return 0;
    }

    return (st->state == NGX_ANYTLS_STREAM_CONNECTED
            || st->state == NGX_ANYTLS_STREAM_HALF_CLOSED
            || st->state == NGX_ANYTLS_STREAM_CONNECTING) ? 1 : 0;
}


static ngx_int_t
ngx_anytls_upstream_mux_drain_reads(ngx_anytls_connection_t *ac,
    ngx_anytls_schedule_budget_t *sched)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;
    ngx_connection_t *c;
    ngx_chain_t *cl;
    ngx_buf_t *b;
    ssize_t n;
    size_t size;
    ngx_int_t rc;

    for (q = ngx_queue_head(&ac->upstream_mux.read_ready);
         q != ngx_queue_sentinel(&ac->upstream_mux.read_ready)
         && sched->visited_streams < sched->stream_budget;
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_read_queue);

        st->upstream_read_ready = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);

        if (!ngx_anytls_upstream_mux_stream_readable(st)) {
            continue;
        }

        c = ngx_anytls_upstream_mux_read_conn(st);
        size = ac->conf->buffer_size;
        if (size > NGX_ANYTLS_MAX_FRAME_DATA) {
            size = NGX_ANYTLS_MAX_FRAME_DATA;
        }

        sched->visited_streams++;

        for ( ;; ) {
            if (sched->processed_frames >= sched->frame_budget
                || sched->processed_bytes >= sched->byte_budget)
            {
                ngx_log_debug5(NGX_LOG_DEBUG_STREAM, ngx_anytls_conn_log(ac), 0,
                               "anytls: drain_reads budget st=%ui "
                               "frames=%ui/%ui bytes=%uz/%uz",
                               (ngx_uint_t) st->id,
                               sched->processed_frames, sched->frame_budget,
                               sched->processed_bytes, sched->byte_budget);
                /* Budget exhausted — re-queue stream for next round */
                if (!st->upstream_read_ready
                    && !ngx_anytls_upstream_mux_read_blocked(st))
                {
                    st->upstream_read_ready = 1;
                    ngx_queue_insert_tail(&ac->upstream_mux.read_ready,
                                          &st->upstream_read_queue);
                }
                break;
            }

            if (ac->output_pressure
                || !ngx_anytls_client_mux_has_room(ac, size))
            {
                ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ngx_anytls_conn_log(ac), 0,
                               "anytls: drain_reads block st=%ui "
                               "pressure=%d pend_out=%uz",
                               (ngx_uint_t) st->id, ac->output_pressure,
                               ac->pending_output);
                if (ngx_anytls_upstream_block_read(st, c->read) != NGX_OK) {
                    ngx_anytls_core_stream_close(st);
                }
                goto next_stream;
            }

            /* Clamp read size to remaining byte budget so we never exceed */
            if (sched->processed_bytes + size > sched->byte_budget) {
                size = (sched->byte_budget > sched->processed_bytes)
                       ? (sched->byte_budget - sched->processed_bytes)
                       : 0;
                if (size == 0) {
                    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ngx_anytls_conn_log(ac), 0,
                                   "anytls: drain_reads byte_budget "
                                   "exact st=%ui bytes=%uz/%uz",
                                   (ngx_uint_t) st->id,
                                   sched->processed_bytes,
                                   sched->byte_budget);
                    /* Re-queue, byte budget exactly hit */
                    if (!st->upstream_read_ready
                        && !ngx_anytls_upstream_mux_read_blocked(st))
                    {
                        st->upstream_read_ready = 1;
                        ngx_queue_insert_tail(
                            &ac->upstream_mux.read_ready,
                            &st->upstream_read_queue);
                    }
                    break;
                }
            }

            cl = ngx_anytls_upstream_get_read_buf(ac, size);
            if (cl == NULL) {
                ngx_anytls_core_stream_close(st);
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
                    ngx_anytls_core_stream_close(st);
                    goto next_stream;
                }
                n = ngx_anytls_transport_read(c, b->last + 2, size - 2);
                if (n == NGX_AGAIN) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    break;
                }
                if (n == NGX_ERROR) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    ngx_anytls_core_stream_close(st);
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

                    (void) ngx_anytls_core_stream_send_fin(st);
                    goto next_stream;
                }
                if (n == NGX_ERROR) {
                    ngx_anytls_upstream_free_read_buf(ac, cl);
                    ngx_anytls_core_stream_close(st);
                    goto next_stream;
                }

                b->last += n;
            }

            rc = ngx_anytls_client_mux_queue_chain_frame(ac, st, NGX_ANYTLS_CMD_PSH,
                                              st->id, cl, (size_t) n, 1);
            if (rc == NGX_AGAIN) {
                ngx_anytls_upstream_free_read_buf(ac, cl);
                if (ngx_anytls_upstream_block_read(st, c->read) != NGX_OK) {
                    ngx_anytls_core_stream_close(st);
                }
                goto next_stream;
            }
            if (rc != NGX_OK) {
                ngx_anytls_upstream_free_read_buf(ac, cl);
                ngx_anytls_core_stream_close(st);
                goto next_stream;
            }

            ngx_anytls_upstream_state_add_bytes_received(ac->session,
                                                         &st->upstream_state, n);
            st->last_activity = ngx_current_msec;
            sched->processed_frames++;
            sched->processed_bytes += (size_t) n;
        }

        (void) ngx_anytls_transport_arm_read(c);
    next_stream:
        ;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_anytls_upstream_mux_drain_writes(ngx_anytls_connection_t *ac,
    ngx_anytls_schedule_budget_t *sched)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;
    size_t sent;

    for (q = ngx_queue_head(&ac->upstream_mux.write_ready);
         q != ngx_queue_sentinel(&ac->upstream_mux.write_ready)
         && sched->visited_streams < sched->stream_budget
         && sched->processed_frames < sched->frame_budget
         && sched->processed_bytes < sched->byte_budget;
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_write_queue);

        st->upstream_write_ready = 0;
        ngx_queue_remove(q);
        ngx_queue_init(q);

        sent = 0;

        if (ngx_anytls_upstream_send_pending(
                st, sched->byte_budget - sched->processed_bytes,
                &sent)
            == NGX_ERROR)
        {
            ngx_anytls_core_stream_close(st);
            continue;
        }

        st->last_activity = ngx_current_msec;
        sched->visited_streams++;
        sched->processed_frames++;
        sched->processed_bytes += sent;

        /* If more data remains (budget exhausted or stream has more
         * to write), re-queue for the next cycle.  The outer loop
         * stops when stream_budget / frame_budget / byte_budget
         * are hit, so re-queuing here is safe — the stream will be
         * picked up on the next drain_writes call. */
        if (st->pending_in != NULL
            && !st->upstream_write_ready
            && ngx_anytls_upstream_mux_stream_writable(st))
        {
            ngx_log_debug4(NGX_LOG_DEBUG_STREAM, ngx_anytls_conn_log(ac), 0,
                           "anytls: drain_writes requeue st=%ui "
                           "pending=%uz frames=%ui/%ui",
                           (ngx_uint_t) st->id,
                           st->pending_in_bytes,
                           sched->processed_frames,
                           sched->frame_budget);
            st->upstream_write_ready = 1;
            ngx_queue_insert_tail(&ac->upstream_mux.write_ready,
                                  &st->upstream_write_queue);
        }
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
ngx_anytls_upstream_mux_resume_upstream_reads(ngx_anytls_connection_t *ac)
{
    /* Resume blocked reads without touching output_pressure.
     * Used by flush() during normal drain; pressure management
     * is handled separately by mux_drain_client. */
    ac->resumed_streams += ngx_anytls_upstream_mux_process_blocked(ac);
}

void
ngx_anytls_upstream_mux_resume_reads(ngx_anytls_connection_t *ac)
{
    ac->output_pressure = 0;

    /* Release pressure and resume blocked upstream reads */
    ac->resumed_streams += ngx_anytls_upstream_mux_process_blocked(ac);
}


void
ngx_anytls_upstream_mux_stream_output_drained(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    /* Called when a stream's pending output has been drained (sent to client).
     * If this stream was blocked on output, re-enable upstream reads.
     * The global resume path handles this; per-stream resume is
     * a future optimization. */
    if (ngx_anytls_upstream_mux_read_blocked(st)) {
        /* Let the global resume mechanism pick this stream up */
        ngx_anytls_client_mux_resume_upstream_reads(ac);
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


ngx_int_t
ngx_anytls_upstream_mux_open_resolved(ngx_anytls_stream_t *st)
{
    /* Wrapper so resolver.c can go through the upstream mux interface
     * instead of directly calling upstream_open_resolved(). */
    return ngx_anytls_upstream_open_resolved(st);
}


void
ngx_anytls_upstream_mux_on_connect_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    ngx_anytls_upstream_mux_cancel_connect(ac, st);
}


void
ngx_anytls_upstream_mux_on_read_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    ngx_anytls_schedule_budget_t sched;
    ngx_connection_t *c;

    c = (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT)
            ? st->udp : st->upstream;
    if (c == NULL
        || (st->state != NGX_ANYTLS_STREAM_CONNECTED
            && st->state != NGX_ANYTLS_STREAM_HALF_CLOSED))
    {
        return;
    }

    if (!st->upstream_read_ready
        && !ngx_anytls_upstream_mux_read_blocked(st))
    {
        st->upstream_read_ready = 1;
        ngx_queue_insert_tail(&ac->upstream_mux.read_ready,
                              &st->upstream_read_queue);
    }

    sched.frame_budget = NGX_ANYTLS_SCHEDULE_FRAME_BUDGET;
    sched.byte_budget = NGX_ANYTLS_SCHEDULE_BYTE_BUDGET;
    sched.stream_budget = NGX_ANYTLS_SCHEDULE_STREAM_BUDGET;
    sched.processed_frames = 0;
    sched.processed_bytes = 0;
    sched.visited_streams = 0;

    (void) ngx_anytls_upstream_mux_drain_reads(ac, &sched);

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, ngx_anytls_conn_log(ac), 0,
                   "anytls: drain_reads done st=%ui "
                   "frames=%ui bytes=%uz streams=%ui",
                   (ngx_uint_t) st->id,
                   sched.processed_frames, sched.processed_bytes,
                   sched.visited_streams);
}


void
ngx_anytls_upstream_mux_on_write_ready(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    ngx_anytls_schedule_budget_t sched;

    if (!ngx_anytls_upstream_mux_stream_writable(st)) {
        return;
    }

    if (!st->upstream_write_ready) {
        st->upstream_write_ready = 1;
        ngx_queue_insert_tail(&ac->upstream_mux.write_ready,
                              &st->upstream_write_queue);
    }

    sched.frame_budget = NGX_ANYTLS_SCHEDULE_FRAME_BUDGET;
    sched.byte_budget = NGX_ANYTLS_SCHEDULE_BYTE_BUDGET;
    sched.stream_budget = NGX_ANYTLS_SCHEDULE_STREAM_BUDGET;
    sched.processed_frames = 0;
    sched.processed_bytes = 0;
    sched.visited_streams = 0;

    (void) ngx_anytls_upstream_mux_drain_writes(ac, &sched);

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, ngx_anytls_conn_log(ac), 0,
                   "anytls: drain_writes done st=%ui "
                   "frames=%ui bytes=%uz streams=%ui",
                   (ngx_uint_t) st->id,
                   sched.processed_frames, sched.processed_bytes,
                   sched.visited_streams);
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
        if (ngx_anytls_client_mux_queue_frame(ac, st, NGX_ANYTLS_CMD_ALERT,
                                   st->id, &code, 1) != NGX_OK)
        {
            /* Alert frame dropped; still proceed with close */
        }
    }

    /* Close endpoint first so stream_close (called via send_fin) sees
     * st->upstream == NULL and skips the redundant close. */
    ngx_anytls_upstream_mux_close_endpoint(st);

    ngx_anytls_core_stream_send_fin(st);
}


void
ngx_anytls_upstream_mux_on_timeout(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (st == NULL || st->state == NGX_ANYTLS_STREAM_CLOSED) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ngx_anytls_conn_log(ac), 0,
                  "anytls: upstream timeout for stream %ui",
                  (ngx_uint_t) st->id);

    ngx_anytls_upstream_mux_close_stream(ac, st, 1);
}


void
ngx_anytls_upstream_mux_on_connect_pending(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (st->connect_pending) {
        return;
    }
    st->connect_pending = 1;
    ngx_queue_insert_tail(&ac->upstream_mux.connect_pending,
                          &st->connect_queue);
}

void
ngx_anytls_upstream_mux_cancel_connect(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (st->connect_pending) {
        st->connect_pending = 0;
        ngx_queue_remove(&st->connect_queue);
        ngx_queue_init(&st->connect_queue);
    }
}

static ngx_uint_t
ngx_anytls_upstream_mux_process_blocked(ngx_anytls_connection_t *ac)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;
    ngx_connection_t *c;
    size_t size;
    ngx_uint_t resumed;

    resumed = 0;

    for (q = ngx_queue_head(&ac->blocked_upstream_reads);
         q != ngx_queue_sentinel(&ac->blocked_upstream_reads);
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, upstream_block);

        c = (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT)
                ? st->udp : st->upstream;

        if (c == NULL
            || st->state != NGX_ANYTLS_STREAM_CONNECTED)
        {
            ngx_anytls_upstream_mux_unblock_read(ac, st);
            continue;
        }

        if (ac->output_pressure) {
            return resumed;
        }

        size = ngx_min(ac->conf->buffer_size,
                       (size_t) NGX_ANYTLS_MAX_FRAME_DATA);
        if (!ngx_anytls_client_mux_has_room(ac, size)) {
            return resumed;
        }

        ngx_anytls_upstream_mux_unblock_read(ac, st);

        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ngx_anytls_conn_log(ac), 0,
                       "anytls: upstream resume st=%ui pend_out=%uz "
                       "blocked_qlen=%ui",
                       (ngx_uint_t) st->id, st->pending_out,
                       ngx_queue_size(&ac->blocked_upstream_reads));

        if (ngx_anytls_transport_arm_read(c) != NGX_OK) {
            ngx_anytls_core_stream_close(st);
            return resumed;
        }
        resumed++;
    }

    return resumed;
}


ngx_int_t
ngx_anytls_upstream_mux_on_read_blocked(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_event_t *rev)
{
    return ngx_anytls_upstream_block_read(st, rev);
}

void
ngx_anytls_upstream_mux_unblock_read(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (ngx_anytls_upstream_mux_read_blocked(st)) {
        ngx_queue_remove(&st->upstream_block);
        ngx_queue_init(&st->upstream_block);
        st->upstream_read_blocked = 0;
        st->blocked_by_upstream = 0;
    }
}

void
ngx_anytls_upstream_mux_stream_closing(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (st->upstream_read_ready) {
        ngx_queue_remove(&st->upstream_read_queue);
        ngx_queue_init(&st->upstream_read_queue);
        st->upstream_read_ready = 0;
    }
    if (st->upstream_write_ready) {
        ngx_queue_remove(&st->upstream_write_queue);
        ngx_queue_init(&st->upstream_write_queue);
        st->upstream_write_ready = 0;
    }
    ngx_anytls_upstream_mux_unblock_read(ac, st);
    ngx_anytls_upstream_mux_cancel_connect(ac, st);
}
