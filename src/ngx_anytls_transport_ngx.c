#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event.h>

#include "ngx_anytls_transport_ngx.h"

#define NGX_ANYTLS_UDP_RCVBUF_SIZE  (256 * 1024)
#define NGX_ANYTLS_UDP_SNDBUF_SIZE  (256 * 1024)


ssize_t
ngx_anytls_transport_read(ngx_connection_t *c, u_char *buf, size_t size)
{
    return c->recv(c, buf, size);
}


ssize_t
ngx_anytls_transport_send(ngx_connection_t *c, u_char *data, size_t size)
{
    return c->send(c, data, size);
}


ngx_chain_t *
ngx_anytls_transport_write_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    return c->send_chain(c, in, limit);
}


ngx_int_t
ngx_anytls_transport_arm_read(ngx_connection_t *c)
{
    return ngx_handle_read_event(c->read, 0);
}


ngx_int_t
ngx_anytls_transport_disarm_read(ngx_connection_t *c)
{
    if (c->read->active) {
        return ngx_del_event(c->read, NGX_READ_EVENT, 0);
    }
    return NGX_OK;
}


ngx_int_t
ngx_anytls_transport_arm_write(ngx_connection_t *c)
{
    return ngx_handle_write_event(c->write, 0);
}


ngx_int_t
ngx_anytls_transport_disarm_write(ngx_connection_t *c)
{
    if (c->write->active) {
        return ngx_del_event(c->write, NGX_WRITE_EVENT, 0);
    }
    return NGX_OK;
}


void
ngx_anytls_transport_close(ngx_connection_t *c)
{
    ngx_close_connection(c);
}


ngx_int_t
ngx_anytls_transport_shutdown_write(ngx_connection_t *c)
{
    if (c == NULL || c->fd == (ngx_socket_t) -1) {
        return NGX_OK;
    }
    return ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN);
}


ssize_t
ngx_anytls_transport_sendto(ngx_socket_t fd, u_char *data, size_t len,
    struct sockaddr *addr, socklen_t addrlen)
{
    return sendto(fd, data, len, 0, addr, addrlen);
}


ssize_t
ngx_anytls_transport_recvfrom(ngx_socket_t fd, u_char *buf, size_t size,
    struct sockaddr *from, socklen_t *fromlen)
{
    return recvfrom(fd, buf, size, 0, from, fromlen);
}


void
ngx_anytls_transport_arm_timer(ngx_event_t *ev, ngx_msec_t timeout)
{
    if (ev->timer_set) {
        ngx_del_timer(ev);
    }
    ngx_add_timer(ev, timeout);
}


void
ngx_anytls_transport_disarm_timer(ngx_event_t *ev)
{
    if (ev->timer_set) {
        ngx_del_timer(ev);
    }
}


ngx_connection_t *
ngx_anytls_transport_open_udp(ngx_log_t *log, ngx_uint_t family)
{
    ngx_socket_t fd;
    ngx_connection_t *c;

    fd = ngx_socket((int) family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        return NULL;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_close_socket(fd);
        return NULL;
    }

    {
        int  rcvbuf, sndbuf;

        rcvbuf = NGX_ANYTLS_UDP_RCVBUF_SIZE;
        sndbuf = NGX_ANYTLS_UDP_SNDBUF_SIZE;

        (void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                          (const void *) &rcvbuf, sizeof(int));
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                          (const void *) &sndbuf, sizeof(int));
    }

    c = ngx_get_connection(fd, log);
    if (c == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    if (ngx_add_event(c->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_anytls_transport_close(c);
        return NULL;
    }

    c->recv = ngx_udp_recv;
    return c;
}


ngx_int_t
ngx_anytls_transport_connect(ngx_peer_connection_t *pc)
{
    return ngx_event_connect_peer(pc);
}
