#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"

ngx_anytls_stream_t *
ngx_anytls_stream_find(ngx_anytls_connection_t *ac, uint32_t id)
{
    ngx_rbtree_node_t *node, *sentinel;

    node = ac->streams.root;
    sentinel = ac->streams.sentinel;

    while (node != sentinel) {
        if (id == node->key) {
            return (ngx_anytls_stream_t *) node;
        }
        node = (id < node->key) ? node->left : node->right;
    }

    return NULL;
}

ngx_anytls_stream_t *
ngx_anytls_stream_create(ngx_anytls_connection_t *ac, uint32_t id)
{
    ngx_pool_t *pool;
    ngx_anytls_stream_t *st;

    if (ac->active_streams >= ac->conf->max_streams) {
        return NULL;
    }

    pool = ngx_create_pool(NGX_ANYTLS_STREAM_POOL_SIZE, ac->log);
    if (pool == NULL) {
        return NULL;
    }

    st = ngx_pcalloc(pool, sizeof(ngx_anytls_stream_t));
    if (st == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    st->pool = pool;
    st->ac = ac;
    st->id = id;
    st->state = NGX_ANYTLS_STREAM_INIT;
    st->pending_in_last = &st->pending_in;
    st->out_last = &st->out;
    st->node.key = id;
    ngx_queue_init(&st->ready_queue);
    ngx_queue_init(&st->link);
    ngx_queue_init(&st->uot_pending);

    ngx_rbtree_insert(&ac->streams, &st->node);
    ngx_queue_insert_tail(&ac->stream_list, &st->link);
    ac->active_streams++;

    return st;
}

void
ngx_anytls_stream_mark_ready(ngx_anytls_stream_t *st)
{
    if (!st->queued) {
        ngx_queue_insert_tail(&st->ac->ready_streams, &st->ready_queue);
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
    ngx_anytls_pending_t *p, *n;
    ngx_anytls_connection_t *ac;

    if (st == NULL || st->state == NGX_ANYTLS_STREAM_CLOSED) {
        return;
    }

    ac = st->ac;
    st->state = NGX_ANYTLS_STREAM_CLOSED;
    ngx_anytls_stream_remove_ready(st);
    ngx_anytls_resolver_cancel(st);

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

    p = st->pending_in;
    while (p) {
        n = p->next;
        p = n;
    }

    ngx_rbtree_delete(&ac->streams, &st->node);
    ngx_queue_remove(&st->link);
    ac->active_streams--;
    ngx_destroy_pool(st->pool);
}
