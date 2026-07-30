#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_resolver.h"
#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_uot.h"
#include "ngx_anytls_connection_private.h"

static void ngx_anytls_resolve_handler(ngx_resolver_ctx_t *resolve);

static ngx_int_t
ngx_anytls_resolve_sync(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    ngx_url_t url;

    ngx_pool_t *pool;
    pool = ngx_anytls_stream_pool(st);
    if (pool == NULL) { return NGX_ERROR; }
    if (ngx_anytls_addr_to_url(pool, addr, &url) != NGX_OK
        || url.naddrs == 0)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&addr->sockaddr, sizeof(addr->sockaddr));
    ngx_memcpy(&addr->sockaddr, url.addrs[0].sockaddr, url.addrs[0].socklen);
    addr->socklen = url.addrs[0].socklen;
    addr->has_sockaddr = 1;

    return NGX_OK;
}

ngx_int_t
ngx_anytls_resolve_addr(ngx_anytls_stream_t *st,
    ngx_anytls_resolve_target_e target, ngx_anytls_addr_t *addr)
{
    ngx_resolver_ctx_t              *resolve, temp;
    ngx_stream_anytls_srv_conf_t    *conf;

    if (addr->has_sockaddr) {
        return NGX_OK;
    }

    if (addr->host.len == 0 || addr->host.len > 255) {
        return NGX_ERROR;
    }

    conf = st->ac->conf;
    if (conf->resolver == NULL) {
        return ngx_anytls_resolve_sync(st, addr);
    }

    if (st->resolver_pending) {
        return NGX_AGAIN;
    }

    ngx_memzero(&temp, sizeof(temp));
    temp.name = addr->host;

    resolve = ngx_resolve_start(conf->resolver, &temp);
    if (resolve == NULL) {
        return NGX_ERROR;
    }

    if (resolve == NGX_NO_RESOLVER) {
        return ngx_anytls_resolve_sync(st, addr);
    }

    ngx_pool_t *pool;
    pool = ngx_anytls_stream_pool(st);
    if (pool == NULL) { ngx_resolve_name_done(resolve); return NGX_ERROR; }
    resolve->name.data = ngx_pnalloc(pool, addr->host.len);
    if (resolve->name.data == NULL) {
        ngx_resolve_name_done(resolve);
        return NGX_ERROR;
    }
    ngx_memcpy(resolve->name.data, addr->host.data, addr->host.len);
    resolve->name.len = addr->host.len;
    resolve->handler = ngx_anytls_resolve_handler;
    resolve->data = st;
    resolve->timeout = conf->resolver_timeout;

    ngx_memcpy(st->resolver_domain, addr->host.data, addr->host.len);
    st->resolver_domain[addr->host.len] = '\0';
    st->resolver_domain_len = addr->host.len;
    st->resolver_port = addr->port;
    st->resolver_target = target;
    st->resolver_ctx = resolve;
    st->resolver_pending = 1;

    if (ngx_resolve_name(resolve) != NGX_OK) {
        ngx_anytls_resolver_cancel(st);
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

void
ngx_anytls_resolver_cancel(ngx_anytls_stream_t *st)
{
    if (st == NULL) {
        return;
    }

    if (st->resolver_ctx) {
        ngx_resolve_name_done(st->resolver_ctx);
        st->resolver_ctx = NULL;
    }

    st->resolver_pending = 0;
    st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
    st->resolver_domain_len = 0;
    st->resolver_port = 0;
}

static ngx_int_t
ngx_anytls_resolver_copy_addr(ngx_anytls_stream_t *st,
    ngx_resolver_ctx_t *resolve)
{
    ngx_uint_t i;
    ngx_resolver_addr_t *addr;

    for (i = 0; i < resolve->naddrs; i++) {
        addr = &resolve->addrs[i];

        if (addr->socklen > sizeof(st->target.sockaddr)) {
            continue;
        }

        if (addr->sockaddr->sa_family != AF_INET
            && addr->sockaddr->sa_family != AF_INET6)
        {
            continue;
        }

        ngx_memzero(&st->target.sockaddr, sizeof(st->target.sockaddr));
        ngx_memcpy(&st->target.sockaddr, addr->sockaddr, addr->socklen);
        st->target.socklen = addr->socklen;
        ngx_inet_set_port((struct sockaddr *) &st->target.sockaddr,
                          st->resolver_port);
        st->target.has_sockaddr = 1;
        st->target.port = st->resolver_port;

        return NGX_OK;
    }

    return NGX_ERROR;
}

static void
ngx_anytls_resolve_handler(ngx_resolver_ctx_t *resolve)
{
    ngx_anytls_stream_t          *st;
    ngx_anytls_resolve_target_e  target;

    st = resolve->data;
    if (st == NULL || st->resolver_ctx != resolve) {
        ngx_resolve_name_done(resolve);
        return;
    }

    st->resolver_ctx = NULL;
    st->resolver_pending = 0;
    target = st->resolver_target;

    if (resolve->state || resolve->naddrs == 0 || resolve->addrs == NULL
        || ngx_anytls_resolver_copy_addr(st, resolve) != NGX_OK)
    {
        if (resolve->state) {
            ngx_log_error(NGX_LOG_ERR, st->ac->log, 0,
                          "anytls: resolve \"%*s:%ui\" failed (%i: %s)",
                          (int) st->resolver_domain_len, st->resolver_domain,
                          (ngx_uint_t) st->resolver_port, resolve->state,
                          ngx_resolver_strerror(resolve->state));
        } else {
            ngx_log_error(NGX_LOG_ERR, st->ac->log, 0,
                          "anytls: resolve \"%*s:%ui\" failed",
                          (int) st->resolver_domain_len, st->resolver_domain,
                          (ngx_uint_t) st->resolver_port);
        }

        if (target == NGX_ANYTLS_RESOLVE_TCP) {
            ngx_resolve_name_done(resolve);
            st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
            st->resolver_domain_len = 0;
            st->resolver_port = 0;
            (void) ngx_anytls_client_mux_send_synack(st, (u_char *) "resolve failed",
                                          sizeof("resolve failed") - 1);
        } else if (target == NGX_ANYTLS_RESOLVE_UOT_PACKET) {
            ngx_resolve_name_done(resolve);
            ngx_anytls_uot_packet_resolve_failed(st);
            return;
        } else {
            ngx_resolve_name_done(resolve);
            st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
            st->resolver_domain_len = 0;
            st->resolver_port = 0;
        }

        ngx_anytls_stream_close(st);
        return;
    }

    ngx_resolve_name_done(resolve);

    if (target == NGX_ANYTLS_RESOLVE_TCP) {
        st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
        st->resolver_domain_len = 0;
        st->resolver_port = 0;
        if (ngx_anytls_upstream_mux_open_resolved(st) != NGX_OK) {
            ngx_anytls_stream_close(st);
        }
        return;
    }

    if (target == NGX_ANYTLS_RESOLVE_UOT_CONNECT) {
        st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
        st->resolver_domain_len = 0;
        st->resolver_port = 0;
        if (ngx_anytls_uot_resolved(st) != NGX_OK) {
            ngx_anytls_stream_close(st);
        }
        return;
    }

    if (target == NGX_ANYTLS_RESOLVE_UOT_PACKET) {
        if (ngx_anytls_uot_packet_resolved(st) != NGX_OK) {
            ngx_anytls_stream_close(st);
        }
        return;
    }

    st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
    st->resolver_domain_len = 0;
    st->resolver_port = 0;
}
