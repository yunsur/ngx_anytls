#ifndef NGX_ANYTLS_TRANSPORT_NGX_H_INCLUDED
#define NGX_ANYTLS_TRANSPORT_NGX_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


/* Transport layer — abstracts nginx event/socket operations.
 *
 * Core/mux code calls these instead of directly using nginx APIs.
 * The nginx implementation is in transport_ngx.c.
 */

ssize_t ngx_anytls_transport_read(ngx_connection_t *c, u_char *buf,
    size_t size);
ssize_t ngx_anytls_transport_send(ngx_connection_t *c, u_char *data,
    size_t size);
ngx_chain_t *ngx_anytls_transport_write_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
ngx_int_t ngx_anytls_transport_arm_read(ngx_connection_t *c);
ngx_int_t ngx_anytls_transport_disarm_read(ngx_connection_t *c);
ngx_int_t ngx_anytls_transport_arm_write(ngx_connection_t *c);
ngx_int_t ngx_anytls_transport_disarm_write(ngx_connection_t *c);
void ngx_anytls_transport_close(ngx_connection_t *c);
ngx_int_t ngx_anytls_transport_shutdown_write(ngx_connection_t *c);
ssize_t ngx_anytls_transport_sendto(ngx_socket_t fd, u_char *data,
    size_t len, struct sockaddr *addr, socklen_t addrlen);
ssize_t ngx_anytls_transport_recvfrom(ngx_socket_t fd, u_char *buf,
    size_t size, struct sockaddr *from, socklen_t *fromlen);
ngx_connection_t *ngx_anytls_transport_open_udp(ngx_log_t *log,
    ngx_uint_t family);
void ngx_anytls_transport_arm_timer(ngx_event_t *ev, ngx_msec_t timeout);
void ngx_anytls_transport_disarm_timer(ngx_event_t *ev);


#endif
