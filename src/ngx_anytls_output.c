#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_output.h"
#include "ngx_anytls_stream.h"

ngx_int_t
ngx_anytls_queue_frame(ngx_anytls_connection_t *ac, ngx_anytls_stream_t *st,
    ngx_uint_t cmd, uint32_t stream_id, u_char *data, size_t len)
{
    ngx_anytls_out_frame_t *f, **last;
    ngx_chain_t *cl;
    ngx_buf_t *b;
    u_char *p;

    if (len > NGX_ANYTLS_MAX_FRAME_DATA) {
        return NGX_ERROR;
    }

    if (ac->pending_output + NGX_ANYTLS_FRAME_HEADER_LEN + len
        > ac->conf->max_pending_output)
    {
        return NGX_AGAIN;
    }

    f = ngx_pcalloc(ac->pool, sizeof(ngx_anytls_out_frame_t));
    cl = ngx_alloc_chain_link(ac->pool);
    b = ngx_create_temp_buf(ac->pool, NGX_ANYTLS_FRAME_HEADER_LEN + len);
    if (f == NULL || cl == NULL || b == NULL) {
        return NGX_ERROR;
    }

    p = ngx_anytls_write_frame_header(b->pos, cmd, stream_id, (uint16_t) len);
    if (len && data) {
        p = ngx_cpymem(p, data, len);
    }
    b->last = p;
    cl->buf = b;
    cl->next = NULL;

    f->first = cl;
    f->last = cl;
    f->stream = st;
    f->length = NGX_ANYTLS_FRAME_HEADER_LEN + len;
    f->cmd = cmd;

    if (st == NULL) {
        last = &ac->last_out;
        while (*last) {
            last = &(*last)->next;
        }
        *last = f;
    } else {
        *st->out_last = f;
        st->out_last = &f->next;
        st->pending_out += f->length;
        ngx_anytls_stream_mark_ready(st);
    }

    ac->pending_output += f->length;
    ngx_anytls_post_write(ac);
    return NGX_OK;
}

static void
ngx_anytls_schedule_stream_frames(ngx_anytls_connection_t *ac)
{
    ngx_queue_t *q;
    ngx_anytls_stream_t *st;
    ngx_anytls_out_frame_t *f, **last;
    ngx_uint_t budget;

    budget = 64;
    while (!ngx_queue_empty(&ac->ready_streams) && budget-- != 0) {
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
        st->pending_out -= f->length;

        last = &ac->last_out;
        while (*last) {
            last = &(*last)->next;
        }
        *last = f;

        if (st->out != NULL) {
            ngx_anytls_stream_mark_ready(st);
        }
    }
}

void
ngx_anytls_post_write(ngx_anytls_connection_t *ac)
{
    ngx_connection_t *c;

    c = ac->client;
    if (!ac->write_pending && c && c->write) {
        ac->write_pending = 1;
        ngx_post_event(c->write, &ngx_posted_events);
    }
}

ngx_int_t
ngx_anytls_flush(ngx_anytls_connection_t *ac)
{
    ngx_connection_t *c;
    ngx_chain_t *cl, *tail;
    ngx_anytls_out_frame_t *f, *next;

    c = ac->client;
    if (c->error) {
        return NGX_ERROR;
    }

    ngx_anytls_schedule_stream_frames(ac);

    if (ac->unsent == NULL) {
        cl = NULL;
        for (f = ac->last_out; f; f = next) {
            next = f->next;
            f->last->next = cl;
            cl = f->first;
            f->next = NULL;
        }
        ac->last_out = NULL;

        /* Reverse back to FIFO order. */
        tail = NULL;
        while (cl) {
            ngx_chain_t *n = cl->next;
            cl->next = tail;
            tail = cl;
            cl = n;
        }
        ac->unsent = tail;
    }

    if (ac->unsent == NULL) {
        return NGX_OK;
    }

    ac->unsent = c->send_chain(c, ac->unsent, 0);
    if (ac->unsent == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ac->unsent != NULL) {
        return NGX_AGAIN;
    }

    ac->pending_output = 0;
    return NGX_OK;
}
