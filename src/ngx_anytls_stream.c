#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_output.h"
#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_upstream_state.h"


ngx_int_t
ngx_anytls_mux_mark_closing(ngx_anytls_stream_t *st)
{
    if (st == NULL || st->closing) {
        return NGX_OK;
    }

    st->closing = 1;
    ngx_queue_insert_tail(&st->ac->closing_streams, &st->closing_queue);

    if (st->upstream) {
        ngx_close_connection(st->upstream);
        st->upstream = NULL;
    }
    if (st->udp) {
        ngx_close_connection(st->udp);
        st->udp = NULL;
    }

    ngx_anytls_upstream_discard_pending(st);
    ngx_anytls_upstream_state_finalize(st->ac->session, &st->upstream_state);

    if (st->upstream_read_blocked) {
        ngx_queue_remove(&st->upstream_block);
        ngx_queue_init(&st->upstream_block);
        st->upstream_read_blocked = 0;
        st->blocked_by_upstream = 0;
    }

    if (st->connect_pending) {
        ngx_queue_remove(&st->connect_queue);
        ngx_queue_init(&st->connect_queue);
        st->connect_pending = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, st->ac->log, 0,
                   "anytls: stream %ui marked closing via mux",
                   (ngx_uint_t) st->id);

    return NGX_OK;
}

#define NGX_ANYTLS_STREAM_HT_TOMB ((void *) 1)

static ngx_anytls_stream_t *
ngx_anytls_stream_ht_find(ngx_anytls_connection_t *ac, uint32_t id)
{
    uint32_t idx, i;
    ngx_anytls_stream_t *st;

    idx = id & ac->stream_ht_mask;

    for (i = 0; i <= ac->stream_ht_mask; i++) {
        st = ac->stream_ht[idx];
        if (st == NULL) {
            return NULL;
        }
        if (st != NGX_ANYTLS_STREAM_HT_TOMB && st->id == id) {
            return st;
        }
        idx = (idx + 1) & ac->stream_ht_mask;
    }

    return NULL;
}


static ngx_int_t
ngx_anytls_stream_ht_insert(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    uint32_t idx, i;

    idx = st->id & ac->stream_ht_mask;

    for (i = 0; i <= ac->stream_ht_mask; i++) {
        if (ac->stream_ht[idx] == NULL
            || ac->stream_ht[idx] == NGX_ANYTLS_STREAM_HT_TOMB)
        {
            ac->stream_ht[idx] = st;
            return NGX_OK;
        }
        idx = (idx + 1) & ac->stream_ht_mask;
    }

    return NGX_ERROR;
}


static void
ngx_anytls_stream_ht_remove(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    uint32_t idx, i;

    idx = st->id & ac->stream_ht_mask;

    for (i = 0; i <= ac->stream_ht_mask; i++) {
        if (ac->stream_ht[idx] == st) {
            ac->stream_ht[idx] = NGX_ANYTLS_STREAM_HT_TOMB;
            return;
        }
        idx = (idx + 1) & ac->stream_ht_mask;
    }
}


ngx_anytls_stream_t *
ngx_anytls_stream_find(ngx_anytls_connection_t *ac, uint32_t id)
{
    ngx_anytls_stream_t *st;

    st = ngx_anytls_stream_ht_find(ac, id);
    if (st == NULL || st->closed_by_protocol) {
        return NULL;
    }

    return st;
}


ngx_uint_t
ngx_anytls_stream_exists(ngx_anytls_connection_t *ac, uint32_t id)
{
    return ngx_anytls_stream_ht_find(ac, id) != NULL;
}


ngx_anytls_stream_t *
ngx_anytls_stream_create(ngx_anytls_connection_t *ac, uint32_t id)
{
    ngx_anytls_stream_t *st;

    if (ac->active_streams >= ac->conf->max_streams
        || ngx_anytls_stream_exists(ac, id))
    {
        return NULL;
    }

    st = ngx_pcalloc(ac->pool, sizeof(ngx_anytls_stream_t));
    if (st == NULL) {
        return NULL;
    }

    st->pool = NULL;
    st->ac = ac;
    st->id = id;
    st->state = NGX_ANYTLS_STREAM_INIT;
    st->pending_in_last = &st->pending_in;
    st->out_last = &st->out;
    ngx_queue_init(&st->ready_queue);
    ngx_queue_init(&st->link);
    ngx_queue_init(&st->upstream_block);
    ngx_queue_init(&st->upstream_read_queue);
    ngx_queue_init(&st->upstream_write_queue);
    ngx_queue_init(&st->connect_queue);
    ngx_queue_init(&st->closing_queue);
    ngx_queue_init(&st->uot_pending);

    if (ngx_anytls_stream_ht_insert(ac, st) != NGX_OK) {
        return NULL;
    }
    ngx_queue_insert_tail(&ac->stream_list, &st->link);
    ac->active_streams++;

    return st;
}


void
ngx_anytls_stream_mark_closed_by_protocol(ngx_anytls_stream_t *st)
{
    if (st == NULL || st->closed_by_protocol) {
        return;
    }

    st->closed_by_protocol = 1;
    st->in_closed = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, st->ac->log, 0,
                   "anytls: stream %ui logically closed by protocol",
                   (ngx_uint_t) st->id);
}


ngx_int_t
ngx_anytls_stream_send_fin_and_close(ngx_anytls_stream_t *st)
{
    ngx_int_t rc;

    if (st == NULL) {
        return NGX_OK;
    }

    ngx_anytls_stream_mark_closed_by_protocol(st);
    st->out_closed = 1;

    if (!st->fin_queued && !st->fin_sent) {
        rc = ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_FIN,
                                    st->id, NULL, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    ngx_anytls_stream_close(st);

    return NGX_OK;
}


void
ngx_anytls_stream_mark_ready(ngx_anytls_stream_t *st)
{
    if (!st->queued) {
        if (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT) {
            ngx_queue_insert_head(&st->ac->ready_streams, &st->ready_queue);
        } else {
            ngx_queue_insert_tail(&st->ac->ready_streams, &st->ready_queue);
        }
        st->queued = 1;
    }
}


void
ngx_anytls_stream_remove_ready(ngx_anytls_stream_t *st)
{
    if (st->queued) {
        ngx_queue_remove(&st->ready_queue);
        ngx_queue_init(&st->ready_queue);
        st->queued = 0;
    }
}


void
ngx_anytls_stream_close(ngx_anytls_stream_t *st)
{
    ngx_anytls_connection_t *ac;
    ngx_anytls_out_frame_t *f, *next;
    ngx_uint_t was_closing;

    if (st == NULL || st->state == NGX_ANYTLS_STREAM_CLOSED) {
        return;
    }

    ac = st->ac;

    ngx_anytls_stream_mark_closed_by_protocol(st);

    /* Clean up mux queue state */
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

    if (!ac->closing && st->queued_frames != 0) {
        st->state = NGX_ANYTLS_STREAM_CLOSING;
        st->delayed_close = 1;

        if (!st->closing) {
            st->closing = 1;
            ngx_queue_insert_tail(&ac->closing_streams, &st->closing_queue);
        }

        ngx_log_debug4(NGX_LOG_DEBUG_STREAM, ac->log, 0,
                       "anytls: delay stream %ui close, queued_frames:%ui "
                       "pending_out:%uz pending_in:%uz",
                       (ngx_uint_t) st->id, st->queued_frames,
                       st->pending_out, st->pending_in_bytes);

        ngx_anytls_resolver_cancel(st);

        if (st->upstream) {
            ngx_close_connection(st->upstream);
            st->upstream = NULL;
        }
        if (st->udp) {
            ngx_close_connection(st->udp);
            st->udp = NULL;
        }

        ngx_anytls_upstream_discard_pending(st);
        ngx_anytls_upstream_state_finalize(ac->session, &st->upstream_state);
        if (st->upstream_read_blocked) {
            ngx_queue_remove(&st->upstream_block);
            ngx_queue_init(&st->upstream_block);
            st->upstream_read_blocked = 0;
            st->blocked_by_upstream = 0;
        }
        if (st->connect_pending) {
            ngx_queue_remove(&st->connect_queue);
            ngx_queue_init(&st->connect_queue);
            st->connect_pending = 0;
        }
        return;
    }

    if (st->upstream_read_blocked) {
        ngx_queue_remove(&st->upstream_block);
        ngx_queue_init(&st->upstream_block);
        st->upstream_read_blocked = 0;
        st->blocked_by_upstream = 0;
    }

    st->state = NGX_ANYTLS_STREAM_CLOSED;
    st->delayed_close = 0;
    st->ready_out = 0;
    st->blocked_by_client = 0;
    was_closing = st->closing;
    st->closing = 0;
    st->upstream_read_ready = 0;
    st->upstream_write_ready = 0;
    ngx_anytls_stream_remove_ready(st);
    ngx_anytls_resolver_cancel(st);
    ngx_anytls_upstream_state_finalize(ac->session, &st->upstream_state);

    for (f = st->out; f; f = next) {
        next = f->next;
        if (ac->pending_output >= f->length) {
            ac->pending_output -= f->length;
        } else {
            ac->pending_output = 0;
        }
        if (ac->frames) {
            ac->frames--;
        }
        if (st->queued_frames) {
            st->queued_frames--;
        }
        if (f->own_payload && f->payload_buf.start) {
            ngx_free(f->payload_buf.start);
        }
        if (f->recycle_payload && f->payload) {
            ngx_anytls_upstream_free_read_buf(ac, f->payload);
            f->payload = NULL;
        }
    }
    st->out = NULL;
    st->out_last = &st->out;
    st->pending_out = 0;

    if (st->upstream) {
        ngx_close_connection(st->upstream);
        st->upstream = NULL;
    }
    if (st->udp) {
        ngx_close_connection(st->udp);
        st->udp = NULL;
    }
    while (!ngx_queue_empty(&st->uot_pending)) {
        ngx_queue_remove(ngx_queue_head(&st->uot_pending));
    }
    st->uot_pending_count = 0;
    st->uot_pending_bytes = 0;

    ngx_anytls_upstream_discard_pending(st);

    if (st->upstream_read_blocked) {
        ngx_queue_remove(&st->upstream_block);
        ngx_queue_init(&st->upstream_block);
        st->upstream_read_blocked = 0;
        st->blocked_by_upstream = 0;
    }
    if (st->connect_pending) {
        ngx_queue_remove(&st->connect_queue);
        ngx_queue_init(&st->connect_queue);
        st->connect_pending = 0;
    }
    if (was_closing) {
        ngx_queue_remove(&st->closing_queue);
        ngx_queue_init(&st->closing_queue);
    }
    ngx_queue_remove(&st->link);
    ngx_anytls_stream_ht_remove(ac, st);
    ac->active_streams--;
    if (st->pool) { ngx_destroy_pool(st->pool); }
}
