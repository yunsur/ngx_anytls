#ifndef NGX_ANYTLS_SOCKSADDR_H_INCLUDED
#define NGX_ANYTLS_SOCKSADDR_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>

/* largest legal SOCKS address: domain (1 ATYP + 1 len + 255 host + 2
 * port = 259) beats IPv6 (1 + 16 + 2 = 19) */
#define NGX_ANYTLS_MAX_SOCKS_ADDR_LEN  259

typedef enum {
    NGX_ANYTLS_ADDR_TCP = 0,
    NGX_ANYTLS_ADDR_UOT_V1,
    NGX_ANYTLS_ADDR_UOT_V2_CONNECT,
    NGX_ANYTLS_ADDR_UOT_PACKET
} ngx_anytls_addr_mode_e;

typedef struct {
    ngx_uint_t               atyp;
    ngx_str_t                host;
    u_char                   host_buf[NGX_INET6_ADDRSTRLEN];
    uint16_t                 port;
    struct sockaddr_storage  sockaddr;
    socklen_t                socklen;
    ngx_uint_t               has_sockaddr;
    ngx_anytls_addr_mode_e   mode;
    size_t                   consumed;
} ngx_anytls_addr_t;

ngx_int_t ngx_anytls_parse_socksaddr(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_addr_t *addr);
ngx_int_t ngx_anytls_parse_uot_packet(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_addr_t *addr, u_char **payload, size_t *payload_len,
    size_t *consumed);
ngx_int_t ngx_anytls_addr_to_url(ngx_pool_t *pool, ngx_anytls_addr_t *addr,
    ngx_url_t *url);

static ngx_inline void
ngx_anytls_addr_copy(ngx_anytls_addr_t *dst, ngx_anytls_addr_t *src)
{
    *dst = *src;
    if (src->host.data == src->host_buf) {
        ngx_memcpy(dst->host_buf, src->host_buf, sizeof(dst->host_buf));
        dst->host.data = dst->host_buf;
    }
}

#endif
