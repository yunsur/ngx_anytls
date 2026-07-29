#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_upstream_state.h"
#include "ngx_anytls_private.h"

static ngx_stream_upstream_state_t *
ngx_anytls_upstream_state_get(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker)
{
    ngx_stream_upstream_state_t *states;

    if (s == NULL || s->upstream_states == NULL || tracker == NULL
        || !tracker->opened || tracker->index >= s->upstream_states->nelts)
    {
        return NULL;
    }

    states = s->upstream_states->elts;
    return &states[tracker->index];
}


static ngx_int_t
ngx_anytls_upstream_state_copy_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_state_t *state, const ngx_str_t *peer)
{
    ngx_str_t *copy;

    if (peer == NULL || peer->len == 0) {
        return NGX_OK;
    }

    copy = ngx_palloc(s->connection->pool, sizeof(ngx_str_t));
    if (copy == NULL) {
        return NGX_ERROR;
    }

    copy->data = ngx_pnalloc(s->connection->pool, peer->len);
    if (copy->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(copy->data, peer->data, peer->len);
    copy->len = peer->len;
    state->peer = copy;

    return NGX_OK;
}


ngx_int_t
ngx_anytls_upstream_state_open(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker, const ngx_str_t *peer)
{
    ngx_stream_upstream_state_t *state;

    if (s == NULL || s->connection == NULL || tracker == NULL) {
        return NGX_ERROR;
    }

    if (tracker->opened) {
        return NGX_OK;
    }

    if (s->upstream_states == NULL) {
        s->upstream_states = ngx_array_create(s->connection->pool, 1,
                                              sizeof(ngx_stream_upstream_state_t));
        if (s->upstream_states == NULL) {
            return NGX_ERROR;
        }
    }

    state = ngx_array_push(s->upstream_states);
    if (state == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(state, sizeof(ngx_stream_upstream_state_t));
    state->connect_time = (ngx_msec_t) -1;
    state->first_byte_time = (ngx_msec_t) -1;
    state->response_time = (ngx_msec_t) -1;

    if (ngx_anytls_upstream_state_copy_peer(s, state, peer) != NGX_OK) {
        s->upstream_states->nelts--;
        return NGX_ERROR;
    }

    tracker->index = s->upstream_states->nelts - 1;
    tracker->start_time = ngx_current_msec;
    tracker->bytes_sent = 0;
    tracker->bytes_received = 0;
    tracker->opened = 1;
    tracker->finalized = 0;

    return NGX_OK;
}


void
ngx_anytls_upstream_state_add_bytes_sent(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker, off_t bytes)
{
    if (bytes <= 0 || ngx_anytls_upstream_state_get(s, tracker) == NULL
        || tracker->finalized)
    {
        return;
    }

    tracker->bytes_sent += bytes;
}


void
ngx_anytls_upstream_state_add_bytes_received(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker, off_t bytes)
{
    if (bytes <= 0 || ngx_anytls_upstream_state_get(s, tracker) == NULL
        || tracker->finalized)
    {
        return;
    }

    tracker->bytes_received += bytes;
}


void
ngx_anytls_upstream_state_finalize(ngx_stream_session_t *s,
    ngx_anytls_upstream_state_tracker_t *tracker)
{
    ngx_stream_upstream_state_t *state;

    state = ngx_anytls_upstream_state_get(s, tracker);
    if (state == NULL || tracker->finalized) {
        return;
    }

    state->response_time = ngx_current_msec - tracker->start_time;
    state->bytes_sent = tracker->bytes_sent;
    state->bytes_received = tracker->bytes_received;
    tracker->finalized = 1;
}
