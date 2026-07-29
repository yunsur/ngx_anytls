#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event.h>
#include <arpa/inet.h>

#include "ngx_anytls_uot.h"
#include "ngx_anytls_resolver.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream.h"
#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_core.h"
#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_transport_ngx.h"
#include "ngx_anytls_upstream_state.h"

#define NGX_ANYTLS_UOT_MAX_HEADER  21

static ngx_int_t
ngx_anytls_uot_resolve_sync(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    ngx_url_t url;

    if (addr->has_sockaddr) {
        return NGX_OK;
    }

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

static ngx_int_t
ngx_anytls_uot_queue_udp_frame(ngx_anytls_stream_t *st, ngx_chain_t *cl,
    u_char *pos, size_t len)
{
    ngx_buf_t *b;

    b = cl->buf;
    b->pos = pos;
    b->last = pos + len;

    return ngx_anytls_client_mux_queue_chain_frame(st->ac, st, NGX_ANYTLS_CMD_PSH,
                                        st->id, cl, len, 1);
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
    size_t  n, write_off;

    if (len == 0) {
        return NGX_OK;
    }

    if (st->uot_recv_buf == NULL) {
        st->uot_recv_size = 65536;
        ngx_pool_t *pool;
        pool = ngx_anytls_stream_pool(st);
        if (pool == NULL) { return NGX_ERROR; }
        st->uot_recv_buf = ngx_pnalloc(pool, st->uot_recv_size);
        if (st->uot_recv_buf == NULL) {
            return NGX_ERROR;
        }
    }

    write_off = st->uot_recv_pos + st->uot_recv_len;
    if (len > st->uot_recv_size - write_off) {
        if (st->uot_recv_pos) {
            if (st->uot_recv_len) {
                ngx_memmove(st->uot_recv_buf,
                            st->uot_recv_buf + st->uot_recv_pos,
                            st->uot_recv_len);
            }
            write_off = st->uot_recv_len;
            st->uot_recv_pos = 0;
        }

        n = write_off + len;
        if (n > 65536) {
            return NGX_ERROR;
        }

        if (len > st->uot_recv_size - write_off) {
            n = n + (n >> 1);
            if (n > 65536) {
                n = 65536;
            }
            ngx_pool_t *pool;
            pool = ngx_anytls_stream_pool(st);
            if (pool == NULL) { return NGX_ERROR; }
            p = ngx_pnalloc(pool, n);
            if (p == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(p, st->uot_recv_buf + st->uot_recv_pos,
                       st->uot_recv_len);
            st->uot_recv_buf = p;
            st->uot_recv_size = n;
            write_off = st->uot_recv_len;
            st->uot_recv_pos = 0;
        }
    }

    ngx_memcpy(st->uot_recv_buf + write_off, data, len);
    st->uot_recv_len += len;

    return NGX_OK;
}
static ngx_uint_t
ngx_anytls_uot_pending_matches(ngx_anytls_uot_pending_t *pkt, u_char *domain,
    size_t domain_len, uint16_t port)
{
    return pkt->domain_len == domain_len
           && pkt->port == port
           && ngx_memcmp(pkt->domain, domain, domain_len) == 0;
}

static ngx_int_t
ngx_anytls_uot_enqueue_pending(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr,
    u_char *payload, size_t payload_len)
{
    ngx_anytls_uot_pending_t *pkt;
    u_char *p;

    if (addr->host.len == 0 || addr->host.len > 255 || payload_len == 0) {
        return NGX_OK;
    }

    if (st->uot_pending_count >= st->ac->conf->uot_pending_packets
        || st->uot_pending_bytes + payload_len > st->ac->conf->uot_pending_bytes)
    {
        ngx_log_error(NGX_LOG_WARN, st->ac->log, 0,
                      "anytls: UoT pending packet queue full, dropping packet");
        return NGX_OK;
    }

    ngx_pool_t *pool;
    pool = ngx_anytls_stream_pool(st);
    if (pool == NULL) { return NGX_ERROR; }
    pkt = ngx_pcalloc(pool, sizeof(ngx_anytls_uot_pending_t));
    if (pkt == NULL) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(pool, addr->host.len + payload_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    pkt->domain = p;
    ngx_memcpy(pkt->domain, addr->host.data, addr->host.len);
    p += addr->host.len;

    pkt->payload = p;
    ngx_memcpy(pkt->payload, payload, payload_len);
    pkt->domain_len = addr->host.len;
    pkt->port = addr->port;
    pkt->payload_len = payload_len;

    ngx_queue_insert_tail(&st->uot_pending, &pkt->queue);
    st->uot_pending_count++;
    st->uot_pending_bytes += payload_len;

    return NGX_OK;
}

static void
ngx_anytls_uot_drop_pending_domain(ngx_anytls_stream_t *st, u_char *domain,
    size_t domain_len, uint16_t port)
{
    ngx_queue_t *q, *next;
    ngx_anytls_uot_pending_t *pkt;

    for (q = ngx_queue_head(&st->uot_pending);
         q != ngx_queue_sentinel(&st->uot_pending);
         q = next)
    {
        next = ngx_queue_next(q);
        pkt = ngx_queue_data(q, ngx_anytls_uot_pending_t, queue);

        if (!ngx_anytls_uot_pending_matches(pkt, domain, domain_len, port)) {
            continue;
        }

        ngx_queue_remove(q);
        st->uot_pending_count--;
        st->uot_pending_bytes -= pkt->payload_len;
    }
}

static void
ngx_anytls_uot_clear_pending(ngx_anytls_stream_t *st)
{
    ngx_queue_t *q;

    while (!ngx_queue_empty(&st->uot_pending)) {
        q = ngx_queue_head(&st->uot_pending);
        ngx_queue_remove(q);
    }

    st->uot_pending_count = 0;
    st->uot_pending_bytes = 0;
}

static void
ngx_anytls_uot_log_output_drop(ngx_anytls_stream_t *st)
{
    ngx_msec_t now;

    st->uot_drop_count++;
    now = ngx_current_msec;

    if (st->uot_drop_log_time == 0 || now - st->uot_drop_log_time >= 1000) {
        ngx_log_error(NGX_LOG_WARN, st->ac->log, 0,
                      "anytls: UoT output full, dropped %ui packet(s)",
                      st->uot_drop_count);
        st->uot_drop_log_time = now;
        st->uot_drop_count = 0;
    }
}


static void
ngx_anytls_uot_idle_timeout_handler(ngx_event_t *ev)
{
    ngx_anytls_stream_t *st;

    st = ev->data;
    if (st == NULL || st->state == NGX_ANYTLS_STREAM_CLOSED) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, st->ac->log, 0,
                  "anytls: UoT idle timeout for stream %ui",
                  (ngx_uint_t) st->id);

    ngx_anytls_uot_close(st);
    ngx_anytls_core_stream_send_fin(st);
}


static void
ngx_anytls_uot_arm_idle_timer(ngx_anytls_stream_t *st)
{
    ngx_msec_t timeout;
    ngx_event_t *ev;
    ngx_pool_t *pool;

    if (st->udp == NULL) {
        return;
    }

    timeout = st->ac->conf->resolver_timeout;
    if (timeout == 0) {
        return;
    }

    if (st->uot_timer == NULL) {
        pool = ngx_anytls_stream_pool(st);
        if (pool == NULL) { return; }
        ev = ngx_pcalloc(pool, sizeof(ngx_event_t));
        if (ev == NULL) { return; }
        ev->handler = ngx_anytls_uot_idle_timeout_handler;
        ev->data = st;
        ev->log = st->ac->log;
        st->uot_timer = ev;
    }

    ngx_anytls_transport_arm_timer(st->uot_timer, timeout);
}


static ngx_int_t
ngx_anytls_udp_socket(ngx_anytls_stream_t *st, ngx_uint_t family)
{
    ngx_connection_t *c;

    if (st->udp && st->udp_family == family) {
        return NGX_OK;
    }

    if (st->udp) {
        ngx_anytls_transport_close(st->udp);
        st->udp = NULL;
        st->udp_family = 0;
    }

    if (ngx_anytls_stream_pool(st) == NULL) {
        return NGX_ERROR;
    }

    c = ngx_anytls_transport_open_udp(st->ac->log, family);
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->data = st;
    c->log = st->ac->log;
    c->pool = st->pool;
    c->read->handler = ngx_anytls_udp_read_handler;
    c->write->handler = ngx_anytls_udp_write_handler;
    st->udp = c;
    st->udp_family = family;

    ngx_anytls_uot_arm_idle_timer(st);

    return NGX_OK;
}


static ngx_int_t
ngx_anytls_uot_upstream_state_open(ngx_anytls_stream_t *st,
    ngx_anytls_addr_t *addr)
{
    u_char *p;

    if (st->uot_mode != NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        return NGX_OK;
    }

    if (st->upstream_state.opened) {
        return NGX_OK;
    }

    ngx_pool_t *pool;
    pool = ngx_anytls_stream_pool(st);
    if (pool == NULL) { return NGX_ERROR; }
    st->upstream_name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
    if (st->upstream_name.data == NULL) {
        return NGX_ERROR;
    }

    st->upstream_name.len = ngx_sock_ntop(
        (struct sockaddr *) &addr->sockaddr, addr->socklen,
        st->upstream_name.data, NGX_SOCKADDR_STRLEN, 1);
    if (st->upstream_name.len == 0) {
        p = ngx_snprintf(st->upstream_name.data, NGX_SOCKADDR_STRLEN,
                         "%V:%ui", &addr->host, (ngx_uint_t) addr->port);
        st->upstream_name.len = p - st->upstream_name.data;
    }

    return ngx_anytls_upstream_state_open(st->ac->session, &st->upstream_state,
                                          &st->upstream_name);
}


static ngx_int_t
ngx_anytls_uot_send_resolved(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr,
    u_char *payload, size_t payload_len)
{
    ngx_uint_t family;
    ssize_t n;

    if (payload_len == 0) {
        return NGX_OK;
    }

    if (!addr->has_sockaddr) {
        return NGX_ERROR;
    }

    family = addr->sockaddr.ss_family;
    if (ngx_anytls_udp_socket(st, family) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_anytls_uot_upstream_state_open(st, addr) != NGX_OK) {
        return NGX_ERROR;
    }

    n = ngx_anytls_transport_sendto(st->udp->fd, payload, payload_len,
               (struct sockaddr *) &addr->sockaddr, addr->socklen);
    if (n == -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, st->ac->log, ngx_socket_errno,
                       "anytls: UoT sendto() dropped packet (errno %d)",
                       ngx_socket_errno);
    } else if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        ngx_anytls_upstream_state_add_bytes_sent(st->ac->session,
                                                 &st->upstream_state, n);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_anytls_uot_process_pending(ngx_anytls_stream_t *st);

static ngx_int_t
ngx_anytls_uot_send_domain_packet(ngx_anytls_stream_t *st,
    ngx_anytls_addr_t *addr, u_char *payload, size_t payload_len)
{
    ngx_int_t rc;

    rc = ngx_anytls_uot_enqueue_pending(st, addr, payload, payload_len);
    if (rc != NGX_OK) {
        return rc;
    }

    if (!st->resolver_pending) {
        return ngx_anytls_uot_process_pending(st);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_anytls_uot_send_payload(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr,
    u_char *payload, size_t payload_len)
{
    ngx_int_t rc;

    if (!addr->has_sockaddr && st->uot_mode != NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        return ngx_anytls_uot_send_domain_packet(st, addr, payload,
                                                 payload_len);
    }

    rc = ngx_anytls_uot_resolve_addr(st, addr);
    if (rc == NGX_AGAIN) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_anytls_uot_send_resolved(st, addr, payload, payload_len);
}

static ngx_int_t
ngx_anytls_uot_flush_pending_domain(ngx_anytls_stream_t *st, u_char *domain,
    size_t domain_len, uint16_t port, struct sockaddr_storage *sockaddr,
    socklen_t socklen)
{
    ngx_queue_t *q, *next;
    ngx_anytls_uot_pending_t *pkt;
    ngx_anytls_addr_t addr;

    for (q = ngx_queue_head(&st->uot_pending);
         q != ngx_queue_sentinel(&st->uot_pending);
         q = next)
    {
        next = ngx_queue_next(q);
        pkt = ngx_queue_data(q, ngx_anytls_uot_pending_t, queue);

        if (!ngx_anytls_uot_pending_matches(pkt, domain, domain_len, port)) {
            continue;
        }

        ngx_memzero(&addr, sizeof(addr));
        addr.host.data = pkt->domain;
        addr.host.len = pkt->domain_len;
        addr.port = pkt->port;
        ngx_memcpy(&addr.sockaddr, sockaddr, socklen);
        addr.socklen = socklen;
        addr.has_sockaddr = 1;

        if (ngx_anytls_uot_send_resolved(st, &addr, pkt->payload,
                                         pkt->payload_len) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, st->ac->log, 0,
                          "anytls: UoT pending packet send failed, "
                          "dropping queued packets for \"%*s:%ui\"",
                          (int) domain_len, domain, (ngx_uint_t) port);
            ngx_anytls_uot_drop_pending_domain(st, domain, domain_len, port);
            return NGX_OK;
        }

        ngx_queue_remove(q);
        st->uot_pending_count--;
        st->uot_pending_bytes -= pkt->payload_len;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_anytls_uot_process_pending(ngx_anytls_stream_t *st)
{
    ngx_queue_t *q;
    ngx_anytls_uot_pending_t *pkt;
    ngx_anytls_addr_t addr;
    ngx_int_t rc;

    while (!ngx_queue_empty(&st->uot_pending) && !st->resolver_pending) {
        q = ngx_queue_head(&st->uot_pending);
        pkt = ngx_queue_data(q, ngx_anytls_uot_pending_t, queue);

        ngx_memzero(&addr, sizeof(addr));
        addr.host.data = pkt->domain;
        addr.host.len = pkt->domain_len;
        addr.port = pkt->port;

        st->target = addr;
        rc = ngx_anytls_resolve_addr(st, NGX_ANYTLS_RESOLVE_UOT_PACKET,
                                     &st->target);
        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, st->ac->log, 0,
                          "anytls: resolve UoT packet target \"%V\" failed",
                          &addr.host);
            ngx_anytls_uot_drop_pending_domain(st, pkt->domain,
                                               pkt->domain_len, pkt->port);
            continue;
        }

        rc = ngx_anytls_uot_flush_pending_domain(st, pkt->domain,
                                                 pkt->domain_len, pkt->port,
                                                 &st->target.sockaddr,
                                                 st->target.socklen);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_anytls_uot_open(ngx_anytls_stream_t *st, ngx_anytls_addr_t *addr)
{
    st->upstream_type = NGX_ANYTLS_UPSTREAM_UOT;
    st->uot_mode = addr->mode;
    st->state = NGX_ANYTLS_STREAM_CONNECTED;
    st->uot_request_parsed = (addr->mode != NGX_ANYTLS_ADDR_UOT_V2_CONNECT);

    return ngx_anytls_client_mux_send_synack(st, NULL, 0);
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

    if (st->resolver_pending
        && st->resolver_target != NGX_ANYTLS_RESOLVE_UOT_PACKET)
    {
        return NGX_OK;
    }

    p = st->uot_recv_buf + st->uot_recv_pos;
    left = st->uot_recv_len;

    if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        if (!st->uot_request_parsed) {
            if (left < 1) {
                return NGX_OK;
            }

            is_connect = p[0];
            ngx_pool_t *pool;
            pool = ngx_anytls_stream_pool(st);
            if (pool == NULL) { return NGX_ERROR; }
            rc = ngx_anytls_core_parse_socksaddr(pool, p + 1, left - 1,
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
            st->uot_recv_pos += st->uot_recv_len - left;
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
            ngx_pool_t *pool;
            pool = ngx_anytls_stream_pool(st);
            if (pool == NULL) { return NGX_ERROR; }
            rc = ngx_anytls_core_parse_uot_packet(pool, p, left, &addr,
                                                   &payload,
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

    st->uot_recv_pos += st->uot_recv_len - left;
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
ngx_anytls_uot_packet_resolve_failed(ngx_anytls_stream_t *st)
{
    u_char domain[256];
    size_t domain_len;
    uint16_t port;

    domain_len = st->resolver_domain_len;
    if (domain_len > sizeof(domain)) {
        domain_len = sizeof(domain);
    }
    ngx_memcpy(domain, st->resolver_domain, domain_len);
    port = st->resolver_port;

    st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
    st->resolver_domain_len = 0;
    st->resolver_port = 0;

    if (domain_len) {
        ngx_anytls_uot_drop_pending_domain(st, domain, domain_len, port);
    }

    (void) ngx_anytls_uot_process_pending(st);
}

ngx_int_t
ngx_anytls_uot_packet_resolved(ngx_anytls_stream_t *st)
{
    u_char domain[256];
    size_t domain_len;
    uint16_t port;
    ngx_int_t rc;

    if (!st->target.has_sockaddr) {
        return NGX_ERROR;
    }

    domain_len = st->resolver_domain_len;
    if (domain_len > sizeof(domain)) {
        return NGX_ERROR;
    }
    ngx_memcpy(domain, st->resolver_domain, domain_len);
    port = st->resolver_port;

    st->resolver_target = NGX_ANYTLS_RESOLVE_NONE;
    st->resolver_domain_len = 0;
    st->resolver_port = 0;

    rc = ngx_anytls_uot_flush_pending_domain(st, domain, domain_len, port,
                                             &st->target.sockaddr,
                                             st->target.socklen);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_anytls_uot_process_pending(st);
}

static ngx_int_t
ngx_anytls_uot_read_dgram(ngx_anytls_stream_t *st, ngx_connection_t *c)
{
    ngx_chain_t *cl;
    ngx_buf_t *b;
    u_char *payload, *p;
    ssize_t n;
    size_t len;
    struct sockaddr_storage from;
    socklen_t fromlen;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    cl = ngx_anytls_upstream_get_read_buf(
        st->ac, NGX_ANYTLS_MAX_FRAME_DATA + NGX_ANYTLS_UOT_MAX_HEADER);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;
    payload = b->pos + NGX_ANYTLS_UOT_MAX_HEADER;

    fromlen = sizeof(from);
    n = ngx_anytls_transport_recvfrom(c->fd, payload,
                 NGX_ANYTLS_MAX_FRAME_DATA,
                 (struct sockaddr *) &from, &fromlen);
    if (n == -1) {
        ngx_anytls_upstream_free_read_buf(st->ac, cl);
        if (ngx_socket_errno == NGX_EAGAIN) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        if (n > 65533) {
            ngx_anytls_upstream_free_read_buf(st->ac, cl);
            st->uot_drop_count++;
            ngx_anytls_uot_log_output_drop(st);
            return NGX_OK;
        }
        p = payload - 2;
        p[0] = (u_char) ((size_t) n >> 8);
        p[1] = (u_char) n;
        len = (size_t) n + 2;
        if (ngx_anytls_uot_queue_udp_frame(st, cl, p, len) != NGX_OK) {
            ngx_anytls_upstream_free_read_buf(st->ac, cl);
            ngx_anytls_uot_log_output_drop(st);
            return NGX_AGAIN;
        }
        ngx_anytls_upstream_state_add_bytes_received(st->ac->session,
                                                     &st->upstream_state, n);

    } else if (from.ss_family == AF_INET) {
        if (n > 65527) {
            ngx_anytls_upstream_free_read_buf(st->ac, cl);
            st->uot_drop_count++;
            ngx_anytls_uot_log_output_drop(st);
            return NGX_OK;
        }
        sin = (struct sockaddr_in *) &from;
        p = payload - 9;
        *p++ = 0x00;
        ngx_memcpy(p, &sin->sin_addr.s_addr, 4);
        p += 4;
        *p++ = (u_char) (ntohs(sin->sin_port) >> 8);
        *p++ = (u_char) ntohs(sin->sin_port);
        *p++ = (u_char) ((size_t) n >> 8);
        *p++ = (u_char) n;
        len = (size_t) n + 9;
        if (ngx_anytls_uot_queue_udp_frame(st, cl, payload - 9, len)
            != NGX_OK)
        {
            ngx_anytls_upstream_free_read_buf(st->ac, cl);
            ngx_anytls_uot_log_output_drop(st);
            return NGX_AGAIN;
        }

    } else if (from.ss_family == AF_INET6) {
        if (n > 65515) {
            ngx_anytls_upstream_free_read_buf(st->ac, cl);
            st->uot_drop_count++;
            ngx_anytls_uot_log_output_drop(st);
            return NGX_OK;
        }
        sin6 = (struct sockaddr_in6 *) &from;
        p = payload - 21;
        *p++ = 0x01;
        p = ngx_cpymem(p, &sin6->sin6_addr, 16);
        *p++ = (u_char) (ntohs(sin6->sin6_port) >> 8);
        *p++ = (u_char) ntohs(sin6->sin6_port);
        *p++ = (u_char) ((size_t) n >> 8);
        *p++ = (u_char) n;
        len = (size_t) n + 21;
        if (ngx_anytls_uot_queue_udp_frame(st, cl, payload - 21, len)
            != NGX_OK)
        {
            ngx_anytls_upstream_free_read_buf(st->ac, cl);
            ngx_anytls_uot_log_output_drop(st);
            return NGX_AGAIN;
        }

    } else {
        ngx_anytls_upstream_free_read_buf(st->ac, cl);
    }

    return NGX_OK;
}


void
ngx_anytls_udp_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c;
    ngx_anytls_stream_t *st;
    ngx_int_t rc;

    c = rev->data;
    st = c->data;

    /* Reset idle timer on activity */
    ngx_anytls_uot_arm_idle_timer(st);

    if (st->uot_mode == NGX_ANYTLS_ADDR_UOT_V2_CONNECT) {
        /* Connected UDP: route through upstream mux read_ready */
        ngx_anytls_upstream_mux_on_read_ready(st->ac, st);

        if (st->udp && !st->upstream_read_blocked) {
            (void) ngx_anytls_transport_arm_read(c);
        }
        return;
    }

    /* Packet mode: keep existing recvfrom path, check backpressure */
    if (st->ac->output_pressure) {
        if (!st->upstream_read_blocked) {
            ngx_anytls_upstream_mux_on_read_blocked(st->ac, st, rev);
        }
        return;
    }

    for ( ;; ) {
        rc = ngx_anytls_uot_read_dgram(st, c);
        if (rc == NGX_AGAIN) {
            break;
        }
        if (rc != NGX_OK) {
            ngx_anytls_core_stream_close(st);
            return;
        }
    }

    (void) ngx_anytls_transport_arm_read(c);
}

void
ngx_anytls_udp_write_handler(ngx_event_t *wev)
{
    (void) wev;
}

void
ngx_anytls_uot_close(ngx_anytls_stream_t *st)
{
    ngx_anytls_resolver_cancel(st);
    ngx_anytls_uot_clear_pending(st);

    if (st->uot_timer && st->uot_timer->timer_set) {
        ngx_anytls_transport_disarm_timer(st->uot_timer);
    }

    if (st->udp) {
        ngx_anytls_transport_close(st->udp);
        st->udp = NULL;
        st->udp_family = 0;
    }
}
