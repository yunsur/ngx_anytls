#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_connection.h"
#include "ngx_anytls_client_handler.h"
#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_upstream_mux.h"
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
ngx_anytls_connection_init(ngx_stream_session_t *s,
    ngx_stream_anytls_srv_conf_t *conf)
{
    ngx_connection_t *c;
    ngx_anytls_connection_t *ac;
    size_t read_size;

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
    read_size = ngx_min(conf->buffer_size,
                        NGX_ANYTLS_FRAME_HEADER_LEN
                        + NGX_ANYTLS_MAX_FRAME_DATA);
    ac->read_buf_size = read_size;
    /* read_buf serves dual purpose: recv target AND remnant storage.
     * Must be large enough to hold remnant (up to one full frame)
     * plus a full recv. */
    ac->read_buf = ngx_pnalloc(c->pool,
                               read_size + NGX_ANYTLS_FRAME_HEADER_LEN
                               + NGX_ANYTLS_MAX_FRAME_DATA);
    if (ac->read_buf == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    ac->control_out_last = &ac->control_out;
    ac->data_out_last = &ac->data_out;
    ac->sending_last = &ac->sending;

    ngx_queue_init(&ac->stream_list);
    ngx_queue_init(&ac->ready_streams);
    ngx_queue_init(&ac->blocked_upstream_reads);
    ngx_queue_init(&ac->closing_streams);
    ngx_anytls_upstream_mux_init(ac);

    ac->stream_ht_mask = 0;
    {
        uint32_t size = (uint32_t) (conf->max_streams * 2);
        /* Round up to power of 2 */
        size--;
        size |= size >> 1;
        size |= size >> 2;
        size |= size >> 4;
        size |= size >> 8;
        size |= size >> 16;
        size++;
        if (size < 64) { size = 64; }
        ac->stream_ht_mask = size - 1;
    }
    ac->stream_ht = ngx_pcalloc(c->pool,
                                sizeof(ngx_anytls_stream_t *) * (ac->stream_ht_mask + 1));
    if (ac->stream_ht == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

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

    while (ac->free_read_bufs) {
        ngx_chain_t *cl = ac->free_read_bufs;
        ac->free_read_bufs = cl->next;
        ngx_free(cl->buf->start);
        ngx_free(cl->buf);
        ngx_free(cl);
    }

    while (ac->free_pending_bufs) {
        void *next = *(void **) ac->free_pending_bufs;
        ngx_free(ac->free_pending_bufs);
        ac->free_pending_bufs = next;
    }

    if (ac->fallback) {
        ngx_anytls_transport_close(ac->fallback);
        ac->fallback = NULL;
    }

    ngx_stream_finalize_session(ac->session, rc);
}
