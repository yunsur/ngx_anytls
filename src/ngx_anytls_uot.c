#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event.h>
#include <arpa/inet.h>

#include "ngx_anytls_uot.h"
#include "ngx_anytls_output.h"
#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"

static ngx_int_t
ngx_anytls_uot_resolve_sync(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    ngx_url_t url;

    if (addr->has_sockaddr) {
        return NGX_OK;
    }

    if (ngx_anytls_addr_to_url(st->pool, addr, &url) != NGX_OK
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

static ngx_int_t
ngx_anytls_uot_resolve_addr(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    if (addr->has_sockaddr) {
        return NGX_OK;
    }

    if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT && addr == &st->target) {
        return ngx_anytls_resolve_addr(st, NGX_ANYTLS_RESOLVE_UOT_CONNECT,
                                       addr);
    }

    return ngx_anytls_uot_resolve_sync(st, addr);
}

static ngx_int_t
ngx_anytls_uot_buffer_append(ngx_anytls_stream_t *st, u_char *data, size_t len)
{
    u_char *p;
    size_t  n;

    if (len == 0) {
        return NGX_OK;
    }

    if (st->uot_recv_buf == NULL) {
        st->uot_recv_size = 65536;
        st->uot_recv_buf = ngx_pnalloc(st->pool, st->uot_recv_size);
        if (st->uot_recv_buf == NULL) {
            return NGX_ERROR;
        }
    }

    if (len > st->uot_recv_size - st->uot_recv_len) {
        n = st->uot_recv_len + len;
        if (n > 65536) {
            return NGX_ERROR;
        }

        p = ngx_pnalloc(st->pool, st->uot_recv_size);
        if (p == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(p, st->uot_recv_buf, st->uot_recv_len);
        st->uot_recv_buf = p;
    }

    ngx_memcpy(st->uot_recv_buf + st->uot_recv_len, data, len);
    st->uot_recv_len += len;

    return NGX_OK;
}

static ngx_int_t
ngx_anytls_udp_socket(ngx_anytls_stream_t *st, ngx_uint_t family)
{
    ngx_socket_t fd;
    ngx_connection_t *c;

    if (st->udp && st->udp_family == family) {
        return NGX_OK;
    }

    if (st->udp) {
        ngx_close_connection(st->udp);
        st->udp = NULL;
        st->udp_family = 0;
    }

    fd = ngx_socket((int) family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        return NGX_ERROR;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    c = ngx_get_connection(fd, st->ac->log);
    if (c == NULL) {
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    c->data = st;
    c->log = st->ac->log;
    c->pool = st->pool;
    c->read->handler = ngx_anytls_udp_read_handler;
    c->write->handler = ngx_anytls_udp_write_handler;
    st->udp = c;
    st->udp_family = family;

    if (ngx_add_event(c->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_close_connection(c);
        st->udp = NULL;
        st->udp_family = 0;
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_anytls_uot_send_payload(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr,
    u_char *payload, size_t payload_len)
{
    ngx_uint_t family;

    if (ngx_anytls_uot_resolve_addr(st, addr) != NGX_OK) {
        return NGX_ERROR;
    }

    family = addr->sockaddr.ss_family;
    if (ngx_anytls_udp_socket(st, family) != NGX_OK) {
        return NGX_ERROR;
    }

    (void) sendto(st->udp->fd, payload, payload_len, 0,
                  (struct sockaddr *) &addr->sockaddr, addr->socklen);

    return NGX_OK;
}

ngx_int_t
ngx_anytls_uot_open(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    st->upstream_type = NGX_ANYTLS_UPSTREAM_UOT;
    st->uot_mode = addr->mode;
    st->state = NGX_ANYTLS_STREAM_CONNECTED;
    st->uot_request_parsed = (addr->mode != NGX_ANYTLS_ADDR_UOT_V2_CONNECT);

    st->synack_sent = 1;
    return ngx_anytls_queue_frame(st->ac, NULL, NGX_ANYTLS_CMD_SYNACK,
                                  st->id, NULL, 0);
}

ngx_int_t
ngx_anytls_uot_client_payload(ngx_anytls_stream_t *st, u_char *data, size_t len)
{
    ngx_anytls_addr_t addr;
    u_char *p, *payload;
    size_t payload_len, consumed, left;
    uint16_t plen;
    ngx_int_t rc;
    ngx_uint_t is_connect;

    if (ngx_anytls_uot_buffer_append(st, data, len) != NGX_OK) {
        return NGX_ERROR;
    }

    if (st->resolver_pending) {
        return NGX_OK;
    }

    p = st->uot_recv_buf;
    left = st->uot_recv_len;

    if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        if (!st->uot_request_parsed) {
            if (left < 1) {
                return NGX_OK;
            }

            is_connect = p[0];
            rc = ngx_anytls_parse_socksaddr(st->pool, p + 1, left - 1,
                                            &st->target);
            if (rc == NGX_AGAIN) {
                return NGX_OK;
            }
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            st->uot_mode = is_connect ? NGX_ANYTLS_ADDR_UOT_V2_CONNECT
                                      : NGX_ANYTLS_ADDR_UOT_PACKET;
            st->uot_request_parsed = 1;
            consumed = 1 + st->target.consumed;
            p += consumed;
            left -= consumed;
        }
    }

    if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        rc = ngx_anytls_uot_resolve_addr(st, &st->target);
        if (rc == NGX_AGAIN) {
            consumed = st->uot_recv_len - left;
            if (consumed && left) {
                ngx_memmove(st->uot_recv_buf, st->uot_recv_buf + consumed,
                            left);
            }
            st->uot_recv_len = left;
            return NGX_OK;
        }
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        while (left) {
            if (left < 2) {
                break;
            }

            plen = (uint16_t) ((p[0] << 8) | p[1]);
            if (left - 2 < plen) {
                break;
            }

            if (plen
                && ngx_anytls_uot_send_payload(st, &st->target, p + 2, plen)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }

            p += 2 + plen;
            left -= 2 + plen;
        }

    } else {
        while (left) {
            rc = ngx_anytls_parse_uot_packet(st->pool, p, left, &addr, &payload,
                                         &payload_len, &consumed);
            if (rc == NGX_AGAIN) {
                break;
            }
            if (rc != NGX_OK
                || ngx_anytls_uot_send_payload(st, &addr, payload, payload_len)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }
            p += consumed;
            left -= consumed;
        }
    }

    consumed = st->uot_recv_len - left;
    if (consumed && left) {
        ngx_memmove(st->uot_recv_buf, st->uot_recv_buf + consumed, left);
    }
    st->uot_recv_len = left;

    return NGX_OK;
}

ngx_int_t
ngx_anytls_uot_resolved(ngx_anytls_stream_t *st)
{
    if (st->uot_mode != NGX_ANYTLS_ADDR_UOT_V2_CONNECT
        || !st->target.has_sockaddr)
    {
        return NGX_ERROR;
    }

    return ngx_anytls_uot_client_payload(st, NULL, 0);
}

void
ngx_anytls_udp_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c;
    ngx_anytls_stream_t *st;
    u_char buf[65536], pkt[65536 + 32], *p;
    ssize_t n;
    struct sockaddr_storage from;
    socklen_t fromlen;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    c = rev->data;
    st = c->data;

    for ( ;; ) {
        fromlen = sizeof(from);
        n = recvfrom(c->fd, buf, sizeof(buf), 0, (struct sockaddr *) &from,
                     &fromlen);
        if (n == -1) {
            if (ngx_socket_errno == NGX_EAGAIN) {
                break;
            }
            ngx_anytls_stream_close(st);
            return;
        }

        if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
            if (n > 65533) {
                continue;
            }
            pkt[0] = (u_char) ((size_t) n >> 8);
            pkt[1] = (u_char) n;
            ngx_memcpy(pkt + 2, buf, (size_t) n);
            (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_PSH,
                                          st->id, pkt, (size_t) n + 2);
        } else if (from.ss_family == AF_INET) {
            if (n > 65527) {
                continue;
            }
            sin = (struct sockaddr_in *) &from;
            p = pkt;
            *p++ = 0x00;
            ngx_memcpy(p, &sin->sin_addr.s_addr, 4);
            p += 4;
            *p++ = (u_char) (ntohs(sin->sin_port) >> 8);
            *p++ = (u_char) ntohs(sin->sin_port);
            *p++ = (u_char) ((size_t) n >> 8);
            *p++ = (u_char) n;
            p = ngx_cpymem(p, buf, (size_t) n);
            (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_PSH,
                                          st->id, pkt, (size_t) (p - pkt));
        } else if (from.ss_family == AF_INET6) {
            if (n > 65515) {
                continue;
            }
            sin6 = (struct sockaddr_in6 *) &from;
            p = pkt;
            *p++ = 0x01;
            p = ngx_cpymem(p, &sin6->sin6_addr, 16);
            *p++ = (u_char) (ntohs(sin6->sin6_port) >> 8);
            *p++ = (u_char) ntohs(sin6->sin6_port);
            *p++ = (u_char) ((size_t) n >> 8);
            *p++ = (u_char) n;
            p = ngx_cpymem(p, buf, (size_t) n);
            (void) ngx_anytls_queue_frame(st->ac, st, NGX_ANYTLS_CMD_PSH,
                                          st->id, pkt, (size_t) (p - pkt));
        }
    }
}

void
ngx_anytls_udp_write_handler(ngx_event_t *wev)
{
    (void) wev;
}

void
ngx_anytls_uot_close(ngx_anytls_stream_t *st)
{
    if (st->udp) {
        ngx_close_connection(st->udp);
        st->udp = NULL;
        st->udp_family = 0;
    }
}
