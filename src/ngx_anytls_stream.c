#include <ngx_config.h>
#include "ngx_anytls_client_mux.h"
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_connection.h"
#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_stream_index.h"
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


static ngx_int_t
ngx_anytls_stream_ht_rebuild(ngx_anytls_connection_t *ac,
    uint32_t target_capacity)
{
    ngx_anytls_stream_t **old_ht, **new_ht, *st;
    ngx_queue_t *q;
    uint32_t capacity;

    old_ht = ac->stream_ht;
    capacity = old_ht ? ac->stream_ht_mask + 1 : 0;

    if (old_ht != NULL && target_capacity == capacity) {
        ngx_memzero(old_ht, sizeof(*old_ht) * capacity);
        new_ht = old_ht;

    } else {
        new_ht = ngx_calloc(sizeof(*new_ht) * target_capacity, ac->log);
        if (new_ht == NULL) {
            return NGX_ERROR;
        }
    }

    for (q = ngx_queue_head(&ac->stream_list);
         q != ngx_queue_sentinel(&ac->stream_list);
         q = ngx_queue_next(q))
    {
        st = ngx_queue_data(q, ngx_anytls_stream_t, link);
        if (!ngx_anytls_stream_index_insert((void **) new_ht,
                                             target_capacity - 1, st))
        {
            if (new_ht != old_ht) {
                ngx_free(new_ht);
            }
            return NGX_ERROR;
        }
    }

    if (new_ht != old_ht) {
        ac->stream_ht = new_ht;
        ac->stream_ht_mask = target_capacity - 1;
        if (old_ht != NULL) {
            ngx_free(old_ht);
        }
    }
    ac->stream_ht_tombstones = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_anytls_stream_ht_ensure(ngx_anytls_connection_t *ac)
{
    uint32_t capacity, target_capacity;

    capacity = ac->stream_ht ? ac->stream_ht_mask + 1 : 0;
    if (!ngx_anytls_stream_index_needs_rebuild(
            capacity, ac->active_streams, ac->stream_ht_tombstones))
    {
        return NGX_OK;
    }

    target_capacity = ngx_anytls_stream_index_next_capacity(
        capacity, ac->active_streams, ac->conf->max_streams);
    return ngx_anytls_stream_ht_rebuild(ac, target_capacity);
}


static ngx_anytls_stream_t *
ngx_anytls_stream_ht_find(ngx_anytls_connection_t *ac, uint32_t id)
{
    return ngx_anytls_stream_index_find((void **) ac->stream_ht,
                                         ac->stream_ht_mask, id);
}


static ngx_int_t
ngx_anytls_stream_ht_insert(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    return ngx_anytls_stream_index_insert((void **) ac->stream_ht,
                                           ac->stream_ht_mask, st)
           ? NGX_OK : NGX_ERROR;
}


static ngx_anytls_stream_t *
ngx_anytls_stream_alloc(ngx_anytls_connection_t *ac, uint32_t id)
{
    ngx_anytls_stream_t *st;

    if (ngx_anytls_stream_ht_ensure(ac) != NGX_OK) {
        return NULL;
    }

    st = ngx_alloc(sizeof(ngx_anytls_stream_t), ac->log);
    if (st == NULL) {
        return NULL;
    }
    ngx_memzero(st, sizeof(ngx_anytls_stream_t));
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
        ngx_free(st);
        return NULL;
    }
    ngx_queue_insert_tail(&ac->stream_list, &st->link);
    ac->active_streams++;

    if (ac->active_streams > ac->peak_active_streams) {
        ac->peak_active_streams = ac->active_streams;
    }
    return st;
}


static void
ngx_anytls_stream_ht_remove(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st)
{
    if (ngx_anytls_stream_index_remove((void **) ac->stream_ht,
                                        ac->stream_ht_mask, st))
    {
        ac->stream_ht_tombstones++;
    }
}


static void
ngx_anytls_stream_ht_compact(ngx_anytls_connection_t *ac)
{
    uint32_t capacity;

    if (ac->stream_ht == NULL) {
        return;
    }

    capacity = ac->stream_ht_mask + 1;
    if (ac->active_streams == 0) {
        if (ac->closing) {
            ngx_free(ac->stream_ht);
            ac->stream_ht = NULL;
            ac->stream_ht_mask = 0;
            ac->stream_ht_tombstones = 0;
            return;
        }

        if (capacity == NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY) {
            ngx_memzero(ac->stream_ht, sizeof(*ac->stream_ht) * capacity);
            ac->stream_ht_tombstones = 0;
            return;
        }

        if (ngx_anytls_stream_ht_rebuild(
                ac, NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY) != NGX_OK)
        {
            ngx_memzero(ac->stream_ht, sizeof(*ac->stream_ht) * capacity);
            ac->stream_ht_tombstones = 0;
        }
        return;
    }

    if (ac->stream_ht_tombstones < 64
        || ac->stream_ht_tombstones <= ac->active_streams)
    {
        return;
    }

    (void) ngx_anytls_stream_ht_rebuild(ac, capacity);
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


ngx_anytls_stream_t *
ngx_anytls_stream_create_if_absent(ngx_anytls_connection_t *ac, uint32_t id,
    ngx_uint_t *created)
{
    ngx_anytls_stream_t *st;

    if (created) {
        *created = 0;
    }

    /* Duplicate SYNs for logically closed streams still resolve to the
     * existing table entry.  Reusing an id before close removes it from
     * the hash is invalid, and creating a second entry would strand it
     * behind the closed one. */
    st = ngx_anytls_stream_ht_find(ac, id);
    if (st != NULL) {
        return st;
    }

    if (ac->active_streams >= ac->conf->max_streams) {
        return NULL;
    }

    st = ngx_anytls_stream_alloc(ac, id);

    if (st && created) {
        *created = 1;
    }

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
        if (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT || st->uot_counted) {
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
        st->out = next;
        f->next = NULL;
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
        if (st->pending_out >= f->length) {
            st->pending_out -= f->length;
        } else {
            st->pending_out = 0;
        }
        ngx_anytls_client_mux_discard_frame(ac, f);
    }
    st->out = NULL;
    st->out_last = &st->out;
    st->pending_out = 0;

    if (st->upstream) {
        ngx_anytls_transport_close(st->upstream);
        st->upstream = NULL;
    }
    if (st->upstream_type == NGX_ANYTLS_UPSTREAM_UOT || st->uot_counted) {
        ngx_anytls_uot_close(st);
    }

    ngx_anytls_upstream_discard_pending(st);

    ngx_anytls_upstream_mux_cancel_connect(ac, st);
    if (was_closing) {
        ngx_queue_remove(&st->closing_queue);
        ngx_queue_init(&st->closing_queue);
    }
    ngx_queue_remove(&st->link);
    ac->active_streams--;
    ngx_anytls_connection_release_client_buffer_if_idle(ac);
    ngx_anytls_stream_ht_remove(ac, st);
    ngx_anytls_stream_ht_compact(ac);
    if (st->pool) {
        ngx_destroy_pool(st->pool);
    }
    ngx_free(st);
}
