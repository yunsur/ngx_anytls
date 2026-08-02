#include <ngx_config.h>
#include "ngx_anytls_client_mux.h"
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_upstream_state.h"
#include "ngx_anytls_uot.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_connection_private.h"


ngx_pool_t *
ngx_anytls_stream_pool(ngx_anytls_stream_t *st)
{
    if (st->pool == NULL) {
        st->pool = ngx_create_pool(NGX_ANYTLS_STREAM_POOL_SIZE,
                                   st->ac->log);
    }
    return st->pool;
}


ngx_uint_t
ngx_anytls_stream_is_first_psh(ngx_anytls_stream_t *st)
{
    return st->first_psh_seen ? 0 : 1;
}


void
ngx_anytls_stream_set_first_psh(ngx_anytls_stream_t *st,
    const ngx_anytls_addr_t *addr)
{
    st->first_psh_seen = 1;
    ngx_anytls_addr_copy(&st->target, (ngx_anytls_addr_t *) addr);
}


ngx_uint_t
ngx_anytls_stream_can_accept_payload(ngx_anytls_stream_t *st)
{
    if (st->in_closed
        || st->state == NGX_ANYTLS_STREAM_CLOSING
        || st->state == NGX_ANYTLS_STREAM_CLOSED)
    {
        return 0;
    }
    return 1;
}


ngx_uint_t
ngx_anytls_stream_is_closed_by_protocol(ngx_anytls_stream_t *st)
{
    return st->closed_by_protocol;
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


ngx_anytls_stream_t *
ngx_anytls_stream_resolve(ngx_anytls_connection_t *ac, uint32_t id,
    ngx_anytls_stream_op_e op)
{
    switch (op) {
    case NGX_ANYTLS_STREAM_OP_CREATE:
        return ngx_anytls_stream_create(ac, id);
    case NGX_ANYTLS_STREAM_OP_FIND:
        return ngx_anytls_stream_find(ac, id);
    case NGX_ANYTLS_STREAM_OP_EXISTS:
        return (ngx_anytls_stream_t *) (uintptr_t)
            ngx_anytls_stream_exists(ac, id);
    default:
        return NULL;
    }
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
        rc = ngx_anytls_client_mux_queue_frame(st->ac, st, NGX_ANYTLS_CMD_FIN,
                                    st->id, NULL, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    ngx_anytls_stream_close(st);

    return NGX_OK;
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
    ngx_anytls_upstream_mux_stream_closing(ac, st);

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
            ngx_anytls_transport_close(st->upstream);
            st->upstream = NULL;
        }
        if (st->uot_counted) {
            ngx_anytls_uot_close(st);
        }

        ngx_anytls_upstream_discard_pending(st);
        ngx_anytls_upstream_state_finalize(ac->session, &st->upstream_state);
        if (st->upstream_read_blocked) {
            ngx_queue_remove(&st->upstream_block);
            ngx_queue_init(&st->upstream_block);
            st->upstream_read_blocked = 0;
            st->blocked_by_upstream = 0;
        }
        ngx_anytls_upstream_mux_cancel_connect(ac, st);
        return;
    }

    st->state = NGX_ANYTLS_STREAM_CLOSED;
    st->delayed_close = 0;
    st->ready_out = 0;
    st->blocked_by_client = 0;
    was_closing = st->closing;
    st->closing = 0;
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
        ngx_anytls_transport_close(st->upstream);
        st->upstream = NULL;
    }
    if (st->uot_counted) {
        ngx_anytls_uot_close(st);
    }
    while (!ngx_queue_empty(&st->uot_pending)) {
        ngx_queue_remove(ngx_queue_head(&st->uot_pending));
    }
    st->uot_pending_count = 0;
    st->uot_pending_bytes = 0;

    ngx_anytls_upstream_discard_pending(st);

    ngx_anytls_upstream_mux_cancel_connect(ac, st);
    if (was_closing) {
        ngx_queue_remove(&st->closing_queue);
        ngx_queue_init(&st->closing_queue);
    }
    ngx_queue_remove(&st->link);
    ngx_anytls_stream_ht_remove(ac, st);
    ac->active_streams--;
    if (st->pool) { ngx_destroy_pool(st->pool); }
}
