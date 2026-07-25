#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include <arpa/inet.h>

#include "ngx_anytls_socksaddr.h"

#define NGX_ANYTLS_ATYP_IPV4    1
#define NGX_ANYTLS_ATYP_DOMAIN  3
#define NGX_ANYTLS_ATYP_IPV6    4

#define NGX_ANYTLS_UOT_ATYP_IPV4    0
#define NGX_ANYTLS_UOT_ATYP_IPV6    1
#define NGX_ANYTLS_UOT_ATYP_DOMAIN  2

static ngx_int_t
ngx_anytls_detect_uot(ngx_str_t *host)
{
    ngx_str_t v2 = ngx_string("sp.v2.udp-over-tcp.arpa");
    ngx_str_t v1 = ngx_string("sp.udp-over-tcp.arpa");
    ngx_str_t suffix = ngx_string("udp-over-tcp.arpa");

    if (host->len == v2.len && ngx_strncasecmp(host->data, v2.data, v2.len) == 0)
    {
        return NGX_ANYTLS_ADDR_UOT_V2_CONNECT;
    }

    if (host->len == v1.len && ngx_strncasecmp(host->data, v1.data, v1.len) == 0)
    {
        return NGX_ANYTLS_ADDR_UOT_V1;
    }

    if (host->len >= suffix.len
        && ngx_strncasecmp(host->data + host->len - suffix.len,
                           suffix.data, suffix.len) == 0)
    {
        return NGX_ANYTLS_ADDR_UOT_PACKET;
    }

    return NGX_ANYTLS_ADDR_TCP;
}

ngx_int_t
ngx_anytls_parse_socksaddr(ngx_pool_t *pool, u_char *data, size_t len,
    ngx_anytls_addr_t *addr)
{
    u_char             *p, *last;
    uint16_t            port;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    if (len < 1) {
        return NGX_AGAIN;
    }

    ngx_memzero(addr, sizeof(*addr));
    p = data;
    last = data + len;
    addr->atyp = *p++;

    switch (addr->atyp) {
    case NGX_ANYTLS_ATYP_IPV4:
        if ((size_t) (last - p) < 6) {
            return NGX_AGAIN;
        }
        sin = (struct sockaddr_in *) &addr->sockaddr;
        ngx_memzero(sin, sizeof(*sin));
        sin->sin_family = AF_INET;
        ngx_memcpy(&sin->sin_addr.s_addr, p, 4);
        addr->host.data = ngx_pnalloc(pool, NGX_INET_ADDRSTRLEN);
        if (addr->host.data == NULL) {
            return NGX_ERROR;
        }
        addr->host.len = ngx_inet_ntop(AF_INET, p, addr->host.data,
                                       NGX_INET_ADDRSTRLEN);
        p += 4;
        port = (uint16_t) ((p[0] << 8) | p[1]);
        p += 2;
        sin->sin_port = htons(port);
        addr->port = port;
        addr->socklen = sizeof(*sin);
        addr->has_sockaddr = 1;
        break;

    case NGX_ANYTLS_ATYP_IPV6:
        if ((size_t) (last - p) < 18) {
            return NGX_AGAIN;
        }
        sin6 = (struct sockaddr_in6 *) &addr->sockaddr;
        ngx_memzero(sin6, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        ngx_memcpy(&sin6->sin6_addr, p, 16);
        addr->host.data = ngx_pnalloc(pool, NGX_INET6_ADDRSTRLEN);
        if (addr->host.data == NULL) {
            return NGX_ERROR;
        }
        addr->host.len = ngx_inet_ntop(AF_INET6, p, addr->host.data,
                                       NGX_INET6_ADDRSTRLEN);
        p += 16;
        port = (uint16_t) ((p[0] << 8) | p[1]);
        p += 2;
        sin6->sin6_port = htons(port);
        addr->port = port;
        addr->socklen = sizeof(*sin6);
        addr->has_sockaddr = 1;
        break;

    case NGX_ANYTLS_ATYP_DOMAIN:
        if (p >= last) {
            return NGX_AGAIN;
        }
        if ((size_t) (last - p) < (size_t) p[0] + 3) {
            return NGX_AGAIN;
        }
        addr->host.len = *p++;
        addr->host.data = ngx_pnalloc(pool, addr->host.len);
        if (addr->host.data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(addr->host.data, p, addr->host.len);
        p += addr->host.len;
        port = (uint16_t) ((p[0] << 8) | p[1]);
        p += 2;
        addr->port = port;
        break;

    default:
        return NGX_ERROR;
    }

    addr->consumed = (size_t) (p - data);
    addr->mode = ngx_anytls_detect_uot(&addr->host);
    return NGX_OK;
}

ngx_int_t
ngx_anytls_parse_uot_packet(ngx_pool_t *pool, u_char *data, size_t len,
    ngx_anytls_addr_t *addr, u_char **payload, size_t *payload_len,
    size_t *consumed)
{
    u_char *p, *last, atyp;
    uint16_t plen;
    ngx_int_t rc;

    if (len < 1) {
        return NGX_AGAIN;
    }

    p = data;
    last = data + len;
    atyp = *p;

    if (atyp == NGX_ANYTLS_UOT_ATYP_IPV4) {
        *p = NGX_ANYTLS_ATYP_IPV4;
    } else if (atyp == NGX_ANYTLS_UOT_ATYP_IPV6) {
        *p = NGX_ANYTLS_ATYP_IPV6;
    } else if (atyp == NGX_ANYTLS_UOT_ATYP_DOMAIN) {
        *p = NGX_ANYTLS_ATYP_DOMAIN;
    } else {
        return NGX_ERROR;
    }

    rc = ngx_anytls_parse_socksaddr(pool, p, len, addr);
    *p = atyp;

    if (rc != NGX_OK) {
        return rc;
    }

    if ((size_t) (last - (data + addr->consumed)) < 2) {
        return NGX_AGAIN;
    }

    p = data + addr->consumed;
    plen = (uint16_t) ((p[0] << 8) | p[1]);
    p += 2;

    if ((size_t) (last - p) < plen) {
        return NGX_AGAIN;
    }

    *payload = p;
    *payload_len = plen;
    *consumed = addr->consumed + 2 + plen;
    return NGX_OK;
}

ngx_int_t
ngx_anytls_addr_to_url(ngx_pool_t *pool, ngx_anytls_addr_t *addr, ngx_url_t *url)
{
    size_t len;
    u_char *p;

    ngx_memzero(url, sizeof(*url));
    len = addr->host.len + sizeof(":65535") - 1;
    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    url->url.data = p;
    p = ngx_cpymem(p, addr->host.data, addr->host.len);
    *p++ = ':';
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) addr->port);
    url->url.len = p - url->url.data;
    url->default_port = addr->port;

    if (ngx_parse_url(pool, url) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
