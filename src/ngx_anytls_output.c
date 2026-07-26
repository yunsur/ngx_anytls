#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_output.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream.h"

static ngx_anytls_out_frame_t *ngx_anytls_get_frame(ngx_anytls_connection_t *ac);
static void ngx_anytls_free_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *f);
static void ngx_anytls_reset_frame(ngx_anytls_out_frame_t *f);
static ngx_uint_t ngx_anytls_frame_strong_ref(ngx_uint_t cmd,
    ngx_anytls_stream_t *st);
static void ngx_anytls_default_frame_handler(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *f);
static void ngx_anytls_queue_connection_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *f);
static void ngx_anytls_queue_blocked_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *f);
static ngx_uint_t ngx_anytls_frame_payload_headroom(ngx_chain_t *payload);
static void ngx_anytls_schedule_stream_frames(ngx_anytls_connection_t *ac);
static ngx_uint_t ngx_anytls_frame_sent(ngx_anytls_out_frame_t *f);
static void ngx_anytls_recycle_sent_frames(ngx_anytls_connection_t *ac);
static void ngx_anytls_resume_upstream_reads(ngx_anytls_connection_t *ac);
static void ngx_anytls_write_timeout_handler(ngx_event_t *ev);
static void ngx_anytls_arm_write_timer(ngx_anytls_connection_t *ac);
static void ngx_anytls_disarm_write_timer(ngx_anytls_connection_t *ac);


static ngx_anytls_out_frame_t *
ngx_anytls_get_frame(ngx_anytls_connection_t *ac)
{
    ngx_anytls_out_frame_t *f;

    f = ac->free_frames;
    if (f) {
        ac->free_frames = f->next;
        ac->free_frames_count--;
        ngx_anytls_reset_frame(f);
        return f;
    }

    f = ngx_pcalloc(ac->pool, sizeof(ngx_anytls_out_frame_t));
    return f;
}


static void
ngx_anytls_reset_frame(ngx_anytls_out_frame_t *f)
{
    f->next = NULL;
    f->first = NULL;
    f->last = NULL;
    f->payload = NULL;
    f->stream = NULL;
    f->handler = NULL;
    f->length = 0;
    f->cmd = 0;

    f->header_chain.next = NULL;
    f->payload_chain.next = NULL;
    f->payload_chain.buf = NULL;

    f->payload_buf.start = NULL;
    f->payload_buf.pos = NULL;
    f->payload_buf.last = NULL;
    f->payload_buf.end = NULL;
    f->payload_buf.temporary = 0;
    f->payload_buf.memory = 0;

    f->blocked = 0;
    f->fin = 0;
    f->own_payload = 0;
    f->recycle_payload = 0;
}


static void
ngx_anytls_free_frame(ngx_anytls_connection_t *ac, ngx_anytls_out_frame_t *f)
{
    if (f->own_payload && f->payload_buf.start) {
        ngx_free(f->payload_buf.start);
    }

    if (ac->free_frames_count < NGX_ANYTLS_MAX_FREE_FRAMES) {
        f->next = ac->free_frames;
        ac->free_frames = f;
        ac->free_frames_count++;
    }
}


static ngx_uint_t
ngx_anytls_frame_strong_ref(ngx_uint_t cmd, ngx_anytls_stream_t *st)
{
    if (st == NULL) {
        return 0;
    }

    return cmd == NGX_ANYTLS_CMD_PSH
           || cmd == NGX_ANYTLS_CMD_FIN
           || cmd == NGX_ANYTLS_CMD_SYNACK;
}


static void
ngx_anytls_default_frame_handler(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *f)
{
    ngx_anytls_stream_t *st;

    st = f->stream;

    if (ac->pending_output >= f->length) {
        ac->pending_output -= f->length;
    } else {
        ac->pending_output = 0;
    }

    if (st) {
        if (st->queued_frames) {
            st->queued_frames--;
        }
        if (st->pending_out >= f->length) {
            st->pending_out -= f->length;
        } else {
            st->pending_out = 0;
        }
        if (f->fin) {
            st->fin_sent = 1;
            st->out_closed = 1;
        }
        if (f->recycle_payload && f->payload) {
            ngx_anytls_upstream_free_read_buf(ac, f->payload);
            f->payload = NULL;
        }
    }

    ngx_anytls_free_frame(ac, f);

    if (ac->frames) {
        ac->frames--;
    }

    if (st && st->state == NGX_ANYTLS_STREAM_CLOSING
        && st->queued_frames == 0)
    {
        if (st->delayed_close) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ac->log, 0,
                           "anytls: retry delayed stream %ui close",
                           (ngx_uint_t) st->id);
        }
        ngx_anytls_stream_close(st);
    }
}


static void
ngx_anytls_queue_connection_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *f)
{
    *ac->last_out_last = f;
    ac->last_out_last = &f->next;
}


static void
ngx_anytls_queue_blocked_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_out_frame_t *f)
{
    ngx_anytls_out_frame_t **out;

    for (out = &ac->last_out; *out; out = &(*out)->next) {
        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }
    }

    f->next = *out;
    *out = f;

    if (f->next == NULL) {
        ac->last_out_last = &f->next;
    }
}


static ngx_int_t
ngx_anytls_queue_prepared_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_anytls_out_frame_t *f)
{
    ngx_uint_t strong_ref;

    strong_ref = ngx_anytls_frame_strong_ref(f->cmd, st);

    if (ac->frames >= NGX_ANYTLS_MAX_OUT_FRAMES) {
        ngx_log_error(NGX_LOG_WARN, ac->log, 0,
                      "anytls: output frame guard exceeded");
        ngx_anytls_free_frame(ac, f);
        return NGX_ERROR;
    }

    if (strong_ref && f->cmd == NGX_ANYTLS_CMD_PSH
        && st->queued_frames >= NGX_ANYTLS_MAX_STREAM_FRAMES)
    {
        ngx_log_error(NGX_LOG_WARN, ac->log, 0,
                      "anytls: stream %ui output frame guard exceeded",
                      (ngx_uint_t) st->id);
        ngx_anytls_free_frame(ac, f);
        return NGX_ERROR;
    }

    f->next = NULL;
    f->stream = st;
    f->handler = ngx_anytls_default_frame_handler;
    f->length += NGX_ANYTLS_FRAME_HEADER_LEN;

    if (f->first == NULL) {
        f->header_buf.pos = f->header;
        f->header_buf.last = f->header + NGX_ANYTLS_FRAME_HEADER_LEN;
        f->header_buf.start = f->header;
        f->header_buf.end = f->header + NGX_ANYTLS_FRAME_HEADER_LEN;
        f->header_buf.temporary = 1;
        f->header_buf.memory = 1;

        f->header_chain.buf = &f->header_buf;
        f->header_chain.next = (f->length == NGX_ANYTLS_FRAME_HEADER_LEN)
                               ? NULL : &f->payload_chain;
        f->first = &f->header_chain;
        f->last = (f->header_chain.next == NULL) ? &f->header_chain
                                                 : &f->payload_chain;
    }

    if (strong_ref) {
        st->queued_frames++;
        st->pending_out += f->length;
        if (f->fin) {
            st->fin_queued = 1;
        }
    }

    if (f->blocked || st == NULL) {
        f->blocked = 1;
        ngx_anytls_queue_blocked_frame(ac, f);

    } else if (st) {
        if (strong_ref && f->cmd == NGX_ANYTLS_CMD_PSH
            && st->out == NULL
            && ngx_queue_empty(&ac->ready_streams)
            && ac->pending_output <= ac->conf->max_pending_output / 2
            && st->direct_count < NGX_ANYTLS_MAX_DIRECT_FRAMES)
        {
            ngx_anytls_queue_connection_frame(ac, f);
            st->direct_count++;

        } else {
            *st->out_last = f;
            st->out_last = &f->next;
            ngx_anytls_stream_mark_ready(st);
            st->direct_count = 0;
        }

    } else {
        ngx_anytls_queue_connection_frame(ac, f);
    }

    ac->pending_output += f->length;
    ac->frames++;
    ngx_anytls_post_write(ac);

    return NGX_OK;
}


ngx_int_t
ngx_anytls_queue_frame(ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st,
    ngx_uint_t cmd, uint32_t stream_id, u_char *data, size_t len)
{
    ngx_anytls_out_frame_t *f;

    if (len > NGX_ANYTLS_MAX_FRAME_DATA) {
        return NGX_ERROR;
    }

    if (cmd == NGX_ANYTLS_CMD_PSH && !ngx_anytls_output_has_room(ac, len)) {
        return NGX_AGAIN;
    }

    f = ngx_anytls_get_frame(ac);
    if (f == NULL) {
        return NGX_ERROR;
    }

    f->cmd = cmd;
    f->fin = (cmd == NGX_ANYTLS_CMD_FIN);
    f->blocked = (cmd == NGX_ANYTLS_CMD_PSH) ? 0 : 1;

    if (len) {
        f->payload_buf.start = ngx_alloc(len, ac->log);
        if (f->payload_buf.start == NULL) {
            ngx_anytls_free_frame(ac, f);
            return NGX_ERROR;
        }

        ngx_memcpy(f->payload_buf.start, data, len);
        f->payload_buf.pos = f->payload_buf.start;
        f->payload_buf.last = f->payload_buf.start + len;
        f->payload_buf.end = f->payload_buf.last;
        f->payload_buf.temporary = 1;
        f->own_payload = 1;

        f->payload_chain.buf = &f->payload_buf;
        f->payload_chain.next = NULL;
        f->length = len;
    }

    ngx_anytls_write_frame_header(f->header, cmd, stream_id, (uint16_t) len);
    return ngx_anytls_queue_prepared_frame(ac, st, f);
}


ngx_int_t
ngx_anytls_queue_ref_frame(ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st,
    ngx_uint_t cmd, uint32_t stream_id, u_char *data, size_t len)
{
    ngx_anytls_out_frame_t *f;

    if (len > NGX_ANYTLS_MAX_FRAME_DATA) {
        return NGX_ERROR;
    }

    if (cmd == NGX_ANYTLS_CMD_PSH && !ngx_anytls_output_has_room(ac, len)) {
        return NGX_AGAIN;
    }

    f = ngx_anytls_get_frame(ac);
    if (f == NULL) {
        return NGX_ERROR;
    }

    f->cmd = cmd;
    f->fin = (cmd == NGX_ANYTLS_CMD_FIN);
    f->blocked = (cmd == NGX_ANYTLS_CMD_PSH) ? 0 : 1;

    if (len) {
        f->payload_buf.pos = data;
        f->payload_buf.last = data + len;
        f->payload_buf.start = data;
        f->payload_buf.end = data + len;
        f->payload_buf.memory = 1;

        f->payload_chain.buf = &f->payload_buf;
        f->payload_chain.next = NULL;
        f->length = len;
    }

    ngx_anytls_write_frame_header(f->header, cmd, stream_id, (uint16_t) len);
    return ngx_anytls_queue_prepared_frame(ac, st, f);
}


ngx_int_t
ngx_anytls_queue_chain_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    ngx_chain_t *payload, size_t len, ngx_uint_t recycle_payload)
{
    ngx_anytls_out_frame_t *f;

    if (len > NGX_ANYTLS_MAX_FRAME_DATA) {
        return NGX_ERROR;
    }

    if (cmd == NGX_ANYTLS_CMD_PSH && !ngx_anytls_output_has_room(ac, len)) {
        return NGX_AGAIN;
    }

    f = ngx_anytls_get_frame(ac);
    if (f == NULL) {
        return NGX_ERROR;
    }

    f->cmd = cmd;
    f->fin = (cmd == NGX_ANYTLS_CMD_FIN);
    f->blocked = (cmd == NGX_ANYTLS_CMD_PSH) ? 0 : 1;
    f->length = len;

    if (payload) {
        f->payload = payload;
        f->payload_chain = *payload;
        f->payload_chain.next = NULL;
        f->recycle_payload = recycle_payload ? 1 : 0;

        if (cmd == NGX_ANYTLS_CMD_PSH
            && ngx_anytls_frame_payload_headroom(payload))
        {
            f->payload_chain.buf->pos -= NGX_ANYTLS_FRAME_HEADER_LEN;
            ngx_anytls_write_frame_header(f->payload_chain.buf->pos, cmd,
                                          stream_id, (uint16_t) len);
            f->first = &f->payload_chain;
            f->last = &f->payload_chain;

            return ngx_anytls_queue_prepared_frame(ac, st, f);
        }
    }

    ngx_anytls_write_frame_header(f->header, cmd, stream_id, (uint16_t) len);
    return ngx_anytls_queue_prepared_frame(ac, st, f);
}


ngx_int_t
ngx_anytls_send_synack(ngx_anytls_stream_t *st, u_char *data, size_t len)
{
    if (st == NULL || st->synack_sent) {
        return NGX_OK;
    }

    st->synack_sent = 1;

    if (st->ac->peer_version < 2) {
        return NGX_OK;
    }

    return ngx_anytls_queue_ref_frame(st->ac, st, NGX_ANYTLS_CMD_SYNACK,
                                      st->id, data, len);
}


static void
ngx_anytls_schedule_stream_frames(ngx_anytls_connection_t *ac)
{
    ngx_queue_t *q;
    ngx_anytls_stream_t *st;
    ngx_anytls_out_frame_t *f;
    ngx_uint_t frames;
    size_t bytes, byte_budget;

    frames = 0;
    bytes = 0;
    byte_budget = ac->conf->max_pending_output / 4;
    if (byte_budget > NGX_ANYTLS_MAX_SCHEDULE_BYTES) {
        byte_budget = NGX_ANYTLS_MAX_SCHEDULE_BYTES;
    }
    if (byte_budget == 0) {
        byte_budget = NGX_ANYTLS_MAX_FRAME_DATA;
    }

    while (!ngx_queue_empty(&ac->ready_streams)
           && (frames < NGX_ANYTLS_MIN_SCHEDULE_FRAMES
               || bytes < byte_budget))
    {
        q = ngx_queue_head(&ac->ready_streams);
        st = ngx_queue_data(q, ngx_anytls_stream_t, ready_queue);
        ngx_anytls_stream_remove_ready(st);

        f = st->out;
        if (f == NULL) {
            continue;
        }

        st->out = f->next;
        if (st->out == NULL) {
            st->out_last = &st->out;
        }
        f->next = NULL;

        ngx_anytls_queue_connection_frame(ac, f);
        frames++;
        bytes += f->length;

        if (st->out != NULL) {
            ngx_anytls_stream_mark_ready(st);
        }
    }
}


static ngx_uint_t
ngx_anytls_frame_payload_headroom(ngx_chain_t *payload)
{
    ngx_buf_t *b;

    if (payload == NULL || payload->buf == NULL) {
        return 0;
    }

    b = payload->buf;

    return b->pos >= b->start + NGX_ANYTLS_FRAME_HEADER_LEN;
}


static ngx_uint_t
ngx_anytls_frame_sent(ngx_anytls_out_frame_t *f)
{
    ngx_chain_t *cl;

    for (cl = f->first; cl; cl = cl->next) {
        if (cl->buf->pos != cl->buf->last) {
            return 0;
        }
        if (cl == f->last) {
            break;
        }
    }

    return 1;
}


static void
ngx_anytls_recycle_sent_frames(ngx_anytls_connection_t *ac)
{
    ngx_anytls_out_frame_t *f;

    while (ac->sending) {
        f = ac->sending;
        if (!ngx_anytls_frame_sent(f)) {
            break;
        }

        ac->sending = f->next;
        if (ac->sending == NULL) {
            ac->sending_last = &ac->sending;
        }
        f->next = NULL;

        f->handler(ac, f);
    }
}


static void
ngx_anytls_resume_upstream_reads(ngx_anytls_connection_t *ac)
{
    ngx_queue_t *q, *next;
    ngx_anytls_stream_t *st;
    size_t size;

    for (q = ngx_queue_head(&ac->stream_list);
         q != ngx_queue_sentinel(&ac->stream_list);
         q = next)
    {
        next = ngx_queue_next(q);
        st = ngx_queue_data(q, ngx_anytls_stream_t, link);

        if (!st->upstream_read_blocked || st->upstream == NULL
            || st->state != NGX_ANYTLS_STREAM_CONNECTED)
        {
            continue;
        }

        size = ngx_min(st->ac->conf->buffer_size,
                       (size_t) NGX_ANYTLS_MAX_FRAME_DATA);
        if (!ngx_anytls_output_has_room(ac, size)) {
            return;
        }

        st->upstream_read_blocked = 0;
        if (ngx_handle_read_event(st->upstream->read, 0) != NGX_OK) {
            ngx_anytls_stream_close(st);
            return;
        }
    }
}


static void
ngx_anytls_write_timeout_handler(ngx_event_t *ev)
{
    ngx_anytls_connection_t *ac;

    ac = ev->data;
    if (ac == NULL || ac->closing) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ac->log, 0,
                  "anytls: control write timeout after %M ms",
                  ac->conf->write_timeout);
    ngx_anytls_finalize(ac);
}


static void
ngx_anytls_arm_write_timer(ngx_anytls_connection_t *ac)
{
    ngx_event_t *ev;

    if (ac == NULL || ac->closing || ac->client == NULL
        || ac->conf->write_timeout == 0)
    {
        return;
    }

    ev = &ac->write_timer;
    if (ev->handler == NULL) {
        ev->handler = ngx_anytls_write_timeout_handler;
        ev->data = ac;
        ev->log = ac->log;
    }

    if (!ev->timer_set) {
        ngx_add_timer(ev, ac->conf->write_timeout);
    }
}


static void
ngx_anytls_disarm_write_timer(ngx_anytls_connection_t *ac)
{
    if (ac && ac->write_timer.timer_set) {
        ngx_del_timer(&ac->write_timer);
    }
}


void
ngx_anytls_post_write(ngx_anytls_connection_t *ac)
{
    ngx_connection_t *c;

    c = ac->client;
    if (!ac->write_pending && c && c->write) {
        ac->write_pending = 1;
        ngx_anytls_arm_write_timer(ac);
        ngx_post_event(c->write, &ngx_posted_events);
    }
}


ngx_int_t
ngx_anytls_flush(ngx_anytls_connection_t *ac)
{
    ngx_connection_t *c;
    ngx_chain_t **ll;
    ngx_anytls_out_frame_t *f, *next;

    c = ac->client;
    if (c->error) {
        return NGX_ERROR;
    }

    ngx_anytls_schedule_stream_frames(ac);

    if (ac->unsent == NULL) {
        ll = &ac->unsent;

        for (f = ac->last_out; f; f = next) {
            next = f->next;

            *ll = f->first;
            ll = &f->last->next;

            f->next = NULL;
            *ac->sending_last = f;
            ac->sending_last = &f->next;
        }

        *ll = NULL;
        ac->last_out = NULL;
        ac->last_out_last = &ac->last_out;
    }

    if (ac->unsent == NULL) {
        ngx_anytls_disarm_write_timer(ac);
        return NGX_OK;
    }

    ac->unsent = c->send_chain(c, ac->unsent, 0);
    if (ac->unsent == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ngx_anytls_recycle_sent_frames(ac);
    ngx_anytls_resume_upstream_reads(ac);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ac->unsent != NULL) {
        ngx_anytls_arm_write_timer(ac);
        return NGX_AGAIN;
    }

    if (ac->last_out != NULL || !ngx_queue_empty(&ac->ready_streams)) {
        ngx_anytls_post_write(ac);
    } else {
        ngx_anytls_disarm_write_timer(ac);
    }

    return NGX_OK;
}


ngx_uint_t
ngx_anytls_output_has_room(ngx_anytls_connection_t *ac, size_t len)
{
    return ac->pending_output + NGX_ANYTLS_FRAME_HEADER_LEN + len
           <= ac->conf->max_pending_output;
}
