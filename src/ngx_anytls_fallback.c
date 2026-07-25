#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_fallback.h"
#include "ngx_anytls_upstream_state.h"

ngx_int_t
ngx_anytls_fallback_start(ngx_anytls_connection_t *ac, u_char *raw,
    size_t raw_len)
{
    ngx_str_t target;
    ngx_url_t url;
    ngx_buf_t *b;
    ngx_int_t rc;

    if (ngx_stream_complex_value(ac->session, ac->conf->fallback, &target)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&url, sizeof(url));
    url.url = target;
    if (ngx_parse_url(ac->pool, &url) != NGX_OK || url.naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, ac->log, 0,
                      "anytls: invalid fallback \"%V\"", &target);
        return NGX_ERROR;
    }

    ngx_memzero(&ac->fallback_peer, sizeof(ngx_peer_connection_t));
    ac->fallback_peer.sockaddr = url.addrs[0].sockaddr;
    ac->fallback_peer.socklen = url.addrs[0].socklen;
    ac->fallback_peer.name = &url.addrs[0].name;
    ac->fallback_peer.get = ngx_event_get_peer;
    ac->fallback_peer.log = ac->log;
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
    ac->fallback->log = ac->log;

    b = ngx_create_temp_buf(ac->pool, raw_len + 128);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (ac->conf->fallback_proxy_protocol) {
        b->last = ngx_cpymem(b->last, "PROXY UNKNOWN\r\n",
                             sizeof("PROXY UNKNOWN\r\n") - 1);
    }
    b->last = ngx_cpymem(b->last, raw, raw_len);
    ac->fallback_replay = b;
    ac->state = NGX_ANYTLS_CONN_FALLBACK;

    ac->fallback->read->handler = ngx_anytls_client_read_handler;
    ac->fallback->write->handler = ngx_anytls_client_write_handler;
    ngx_post_event(ac->fallback->write, &ngx_posted_events);

    return NGX_OK;
}
