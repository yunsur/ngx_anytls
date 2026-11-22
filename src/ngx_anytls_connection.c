#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_connection.h"
#include "ngx_anytls_client_handler.h"
#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_upstream_state.h"
#include "ngx_anytls_session_core.h"
#include "ngx_anytls_connection_private.h"


/* Accessor — prefer over direct ac->log access */
ngx_log_t *
ngx_anytls_conn_log(ngx_anytls_connection_t *ac)
{
    return ac->log;
}

void
ngx_anytls_connection_release_client_buffer_if_idle(
    ngx_anytls_connection_t *ac)
{
    if (ac == NULL || ac->client_buffer_processing) {
        return;
    }

    ngx_anytls_client_buffer_release_if_idle(&ac->client_buffer,
                                             ac->active_streams);
}


static ngx_uint_t
ngx_anytls_connection_idle_cache_eligible(ngx_anytls_connection_t *ac)
{
    return ngx_anytls_idle_cache_eligible(
        ac->active_streams, ac->pending_input, ac->pending_output,
        ac->frames, ac->closing);
}


static void
ngx_anytls_connection_trim_caches(ngx_anytls_connection_t *ac)
{
    ngx_anytls_client_mux_trim_cache(ac);
    ngx_anytls_upstream_trim_caches(ac);
    ac->idle_cache_trims++;
}


static void
ngx_anytls_connection_idle_cache_timer_handler(ngx_event_t *ev)
{
    ngx_anytls_connection_t *ac;
    ngx_anytls_idle_cache_action_e action;

    ac = ev->data;
    if (ac == NULL) {
        return;
    }

    action = ngx_anytls_idle_cache_transition(
        &ac->idle_cache_policy, NGX_ANYTLS_IDLE_CACHE_TIMER,
        ngx_anytls_connection_idle_cache_eligible(ac));
    if (action == NGX_ANYTLS_IDLE_CACHE_TRIM) {
        ngx_anytls_connection_trim_caches(ac);
    }
}


void
ngx_anytls_connection_schedule_idle_cache_trim(ngx_anytls_connection_t *ac)
{
    ngx_anytls_idle_cache_action_e action;
    ngx_event_t *ev;

    if (ac == NULL) {
        return;
    }

    action = ngx_anytls_idle_cache_recheck(
        &ac->idle_cache_policy, ac->active_streams, ac->pending_input,
        ac->pending_output, ac->frames, ac->closing);
    if (action != NGX_ANYTLS_IDLE_CACHE_ARM) {
        return;
    }

    ev = &ac->idle_cache_timer;
    ev->handler = ngx_anytls_connection_idle_cache_timer_handler;
    ev->data = ac;
    ev->log = ac->log;
    ev->cancelable = 1;
    ngx_anytls_transport_arm_timer(
        ev, NGX_ANYTLS_IDLE_CACHE_TRIM_DELAY);
}


void
ngx_anytls_connection_cancel_idle_cache_trim(ngx_anytls_connection_t *ac)
{
    ngx_anytls_idle_cache_action_e action;

    if (ac == NULL) {
        return;
    }

    action = ngx_anytls_idle_cache_transition(
        &ac->idle_cache_policy, NGX_ANYTLS_IDLE_CACHE_ACTIVITY, 0);
    if (action == NGX_ANYTLS_IDLE_CACHE_CANCEL) {
        ngx_anytls_transport_disarm_timer(&ac->idle_cache_timer);
    }
}


static void
ngx_anytls_connection_finalize_idle_cache(ngx_anytls_connection_t *ac)
{
    ngx_anytls_idle_cache_action_e action;

    action = ngx_anytls_idle_cache_transition(
        &ac->idle_cache_policy, NGX_ANYTLS_IDLE_CACHE_FINALIZE, 0);
    if (action == NGX_ANYTLS_IDLE_CACHE_CANCEL) {
        ngx_anytls_transport_disarm_timer(&ac->idle_cache_timer);
    }
}


void
ngx_anytls_connection_init(ngx_stream_session_t *s,
    ngx_stream_anytls_srv_conf_t *conf)
{
    ngx_connection_t *c;
    ngx_anytls_connection_t *ac;

    c = s->connection;
    ac = ngx_pcalloc(c->pool, sizeof(ngx_anytls_connection_t));
    if (ac == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ac->session = s;
    ac->client = c;
    ac->pool = c->pool;
    ac->log = c->log;
    ac->conf = conf;
    ac->state = NGX_ANYTLS_CONN_AUTH;
    ngx_anytls_session_core_init(&ac->session_core, conf->padding_md5,
                                  conf->padding_data, conf->padding_data_len);
    ac->read_buf_size = ngx_min(conf->buffer_size,
                                NGX_ANYTLS_CLIENT_BUFFER_MAX_SIZE);
    ngx_anytls_client_buffer_init(&ac->client_buffer);
    ac->control_out_last = &ac->control_out;
    ac->data_out_last = &ac->data_out;
    ac->sending_last = &ac->sending;

    ngx_queue_init(&ac->stream_list);
    ngx_queue_init(&ac->ready_streams);
    ngx_queue_init(&ac->blocked_upstream_reads);
    ngx_queue_init(&ac->closing_streams);
    ngx_anytls_upstream_mux_init(ac);


    ngx_stream_set_ctx(s, ac, ngx_stream_anytls_module);
    c->data = s;
    c->read->handler = ngx_anytls_client_read_handler;
    c->write->handler = ngx_anytls_client_write_handler;

    /* Close connections that never complete the AnyTLS handshake
     * (aligns with nginx stream idle behaviour; default 60s). */
    if (conf->handshake_timeout) {
        ngx_add_timer(c->read, conf->handshake_timeout);
    }

    ngx_anytls_client_read_handler(c->read);
}


void
ngx_anytls_close_if_idle(ngx_anytls_connection_t *ac)
{
    if (ac->closing) {
        return;
    }

    if (ac->active_streams == 0 && ac->pending_output == 0
        && ac->pending_input == 0 && ac->frames == 0)
    {
        ngx_anytls_finalize(ac);
    }
}


void
ngx_anytls_finalize(ngx_anytls_connection_t *ac)
{
    ngx_anytls_finalize_rc(ac, NGX_STREAM_OK);
}


void
ngx_anytls_finalize_rc(ngx_anytls_connection_t *ac, ngx_uint_t rc)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;

    if (ac == NULL || ac->closing) {
        return;
    }

    ngx_anytls_connection_finalize_idle_cache(ac);
    ac->closing = 1;
    ngx_anytls_upstream_state_finalize(ac->session, &ac->fallback_state);
    ngx_anytls_transport_disarm_timer(&ac->write_timer);

    for (q = ngx_queue_head(&ac->stream_list);
         q != ngx_queue_sentinel(&ac->stream_list);
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, link);
        ngx_anytls_stream_mark_closed_by_protocol(st);
        ngx_anytls_stream_close(st);
    }

    if (ac->stream_ht != NULL) {
        ngx_free(ac->stream_ht);
        ac->stream_ht = NULL;
        ac->stream_ht_mask = 0;
        ac->stream_ht_tombstones = 0;
    }

    ngx_anytls_client_mux_destroy(ac);

    ngx_anytls_upstream_trim_caches(ac);

    if (ac->fallback) {
        ngx_anytls_transport_close(ac->fallback);
        ac->fallback = NULL;
    }

    ngx_anytls_client_buffer_destroy(&ac->client_buffer);

    ngx_stream_finalize_session(ac->session, rc);
}
