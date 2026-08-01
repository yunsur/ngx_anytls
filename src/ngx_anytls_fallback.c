#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_fallback.h"
#include "ngx_anytls_connection.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_upstream_state.h"
#include "ngx_anytls_connection_private.h"

static ngx_buf_t *ngx_anytls_fallback_get_buf(ngx_anytls_connection_t *ac,
    ngx_buf_t **slot);
static ngx_int_t ngx_anytls_fallback_flush_buf(ngx_anytls_connection_t *ac,
    ngx_connection_t *to, ngx_buf_t *b, ngx_uint_t upstream);
static ngx_uint_t ngx_anytls_fallback_buf_pending(ngx_buf_t *b);

ngx_int_t
ngx_anytls_fallback_start(ngx_anytls_connection_t *ac, u_char *raw,
    size_t raw_len)
{
    ngx_str_t target;
    ngx_url_t url;
    ngx_buf_t *b;
    ngx_int_t rc;

    if (ac->conf->fallback == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_stream_complex_value(ac->session, ac->conf->fallback, &target)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&url, sizeof(url));
    url.url = target;
    url.default_port = 80;
    if (ngx_parse_url(ac->pool, &url) != NGX_OK || url.naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_anytls_conn_log(ac), 0,
                      "anytls: invalid fallback \"%V\"", &target);
        return NGX_ERROR;
    }

    ngx_memzero(&ac->fallback_peer, sizeof(ngx_peer_connection_t));
    ac->fallback_peer.sockaddr = url.addrs[0].sockaddr;
    ac->fallback_peer.socklen = url.addrs[0].socklen;
    ac->fallback_peer.name = &url.addrs[0].name;
    ac->fallback_peer.get = ngx_event_get_peer;
    ac->fallback_peer.log = ngx_anytls_conn_log(ac);
    ac->fallback_peer.log_error = NGX_ERROR_ERR;

    if (ngx_anytls_upstream_state_open(ac->session, &ac->fallback_state,
                                       ac->fallback_peer.name) != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = ngx_event_connect_peer(&ac->fallback_peer);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        return NGX_ERROR;
    }

    ac->fallback = ac->fallback_peer.connection;
    ac->fallback->data = ac->session;
    ac->fallback->pool = ac->pool;
    ac->fallback->log = ngx_anytls_conn_log(ac);

    b = ngx_create_temp_buf(ac->pool, raw_len + 128);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (ac->conf->fallback_proxy_protocol) {
        u_char *p;

        p = ngx_proxy_protocol_write(ac->client, b->last, b->end);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_WARN, ngx_anytls_conn_log(ac), 0,
                          "anytls: failed to build fallback PROXY protocol "
                          "header, sending raw bytes only");
        } else {
            b->last = p;
        }
    }
    b->last = ngx_cpymem(b->last, raw, raw_len);
    ac->fallback_replay = b;
    ac->state = NGX_ANYTLS_CONN_FALLBACK;

    ac->fallback->read->handler = ngx_anytls_client_read_handler;
    ac->fallback->write->handler = ngx_anytls_client_write_handler;
    ngx_post_event(ac->fallback->write, &ngx_posted_events);

    return NGX_OK;
}

void
ngx_anytls_fallback_write(ngx_anytls_connection_t *ac, ngx_connection_t *c)
{
    ngx_int_t rc;

    if (c != ac->fallback && c != ac->client) {
        return;
    }

    if (!c->write->ready) {
        if (ngx_anytls_transport_arm_write(c) != NGX_OK) {
            ngx_anytls_finalize(ac);
        }
        return;
    }

    if (c == ac->fallback) {
        ngx_anytls_upstream_state_on_connect(ac->session, &ac->fallback_state);

        rc = ngx_anytls_fallback_flush_buf(ac, c, ac->fallback_replay, 1);
        if (rc == NGX_ERROR) {
            ngx_anytls_finalize(ac);
            return;
        }
        if (rc == NGX_AGAIN) {
            return;
        }

        ac->fallback_replay = NULL;

        rc = ngx_anytls_fallback_flush_buf(ac, c, ac->fallback_client_buf, 1);
        if (rc == NGX_ERROR) {
            ngx_anytls_finalize(ac);
            return;
        }
        if (rc == NGX_AGAIN) {
            return;
        }

        if (ngx_anytls_transport_arm_read(ac->client) != NGX_OK
            || ngx_anytls_transport_arm_read(ac->fallback) != NGX_OK)
        {
            ngx_anytls_finalize(ac);
        }

        return;
    }

    rc = ngx_anytls_fallback_flush_buf(ac, c, ac->fallback_upstream_buf, 0);
    if (rc == NGX_ERROR) {
        ngx_anytls_finalize(ac);
        return;
    }
    if (rc == NGX_AGAIN) {
        return;
    }

    if (ngx_anytls_transport_arm_read(ac->fallback) != NGX_OK) {
        ngx_anytls_finalize(ac);
    }
}

void
ngx_anytls_fallback_read(ngx_anytls_connection_t *ac, ngx_connection_t *from,
    ngx_connection_t *to)
{
    ngx_buf_t **slot, *b;
    ssize_t n;
    ngx_int_t rc;
    ngx_uint_t upstream;

    if (to == NULL) {
        ngx_anytls_finalize(ac);
        return;
    }

    upstream = (from == ac->client && to == ac->fallback);
    slot = upstream ? &ac->fallback_client_buf : &ac->fallback_upstream_buf;

    if (upstream && ac->fallback_replay != NULL) {
        if (ngx_anytls_transport_arm_write(to) != NGX_OK) {
            ngx_anytls_finalize(ac);
        }
        return;
    }

    b = ngx_anytls_fallback_get_buf(ac, slot);
    if (b == NULL) {
        ngx_anytls_finalize(ac);
        return;
    }

    if (ngx_anytls_fallback_buf_pending(b)) {
        rc = ngx_anytls_fallback_flush_buf(ac, to, b, upstream);
        if (rc == NGX_ERROR) {
            ngx_anytls_finalize(ac);
        }
        return;
    }

    for ( ;; ) {
        if (b->last == b->end) {
            if (ngx_anytls_transport_arm_write(to) != NGX_OK) {
                ngx_anytls_finalize(ac);
            }
            return;
        }

        n = ngx_anytls_transport_read(from, b->last, (size_t) (b->end - b->last));
        if (n == NGX_AGAIN) {
            break;
        }
        if (n == 0 || n == NGX_ERROR) {
            ngx_anytls_finalize(ac);
            return;
        }

        b->last += n;

        if (!upstream) {
            ngx_anytls_upstream_state_on_first_byte(ac->session,
                                                    &ac->fallback_state);
        }

        rc = ngx_anytls_fallback_flush_buf(ac, to, b, upstream);
        if (rc == NGX_ERROR) {
            ngx_anytls_finalize(ac);
            return;
        }
        if (rc == NGX_AGAIN) {
            return;
        }
    }

    if (ngx_anytls_transport_arm_read(from) != NGX_OK) {
        ngx_anytls_finalize(ac);
    }
}

static ngx_buf_t *
ngx_anytls_fallback_get_buf(ngx_anytls_connection_t *ac, ngx_buf_t **slot)
{
    if (*slot == NULL) {
        *slot = ngx_create_temp_buf(ac->pool, ac->conf->buffer_size);
    }

    return *slot;
}

static ngx_uint_t
ngx_anytls_fallback_buf_pending(ngx_buf_t *b)
{
    return b != NULL && b->pos < b->last;
}

static ngx_int_t
ngx_anytls_fallback_flush_buf(ngx_anytls_connection_t *ac, ngx_connection_t *to,
    ngx_buf_t *b, ngx_uint_t upstream)
{
    ssize_t n;

    while (b != NULL && b->pos < b->last) {
        n = ngx_anytls_transport_send(to, b->pos, (size_t) (b->last - b->pos));
        if (n == NGX_AGAIN) {
            if (ngx_anytls_transport_arm_write(to) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        if (n == NGX_ERROR || n == 0) {
            return NGX_ERROR;
        }

        b->pos += n;

        if (upstream) {
            ngx_anytls_upstream_state_add_bytes_sent(ac->session,
                                                     &ac->fallback_state, n);
        } else {
            ngx_anytls_upstream_state_add_bytes_received(ac->session,
                                                         &ac->fallback_state,
                                                         n);
        }
    }

    if (b != NULL) {
        b->pos = b->start;
        b->last = b->start;
    }

    return NGX_OK;
}
