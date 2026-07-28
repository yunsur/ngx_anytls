#ifndef NGX_ANYTLS_CORE_H_INCLUDED
#define NGX_ANYTLS_CORE_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_anytls_protocol.h"
#include "ngx_anytls_socksaddr.h"

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;
struct ngx_anytls_stream_s;
typedef struct ngx_anytls_stream_s ngx_anytls_stream_t;


/* Core interface — protocol primitives and stream lifecycle.
 *
 * These functions handle AnyTLS frame parsing/encoding, stream state
 * machine, and stream registry operations.  They do NOT call nginx
 * event/timer/socket APIs directly; transport operations go through
 * the transport_ngx layer.
 */

/* Frame I/O — parse/encode helpers */
ngx_int_t ngx_anytls_core_parse_frame(u_char *pos, u_char *last,
    ngx_anytls_frame_t *frame, size_t *consumed);
u_char *ngx_anytls_core_write_frame_header(u_char *p, ngx_uint_t cmd,
    uint32_t stream_id, uint16_t len);

/* Padding */
ngx_int_t ngx_anytls_core_validate_padding(u_char *data, size_t len);

/* SOCKS address parsing */
ngx_int_t ngx_anytls_core_parse_socksaddr(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_addr_t *addr);

/* SHA256 auth helper */
void ngx_anytls_core_sha256(ngx_str_t *password, u_char out[32]);

/* Settings parsing */
ngx_int_t ngx_anytls_core_parse_settings(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_settings_t *settings);

/* Command name (for logging) */
const char *ngx_anytls_core_cmd_name(ngx_uint_t cmd);

/* UoT packet parsing */
ngx_int_t ngx_anytls_core_parse_uot_packet(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_addr_t *addr, u_char **payload,
    size_t *payload_len, size_t *consumed);


/* Stream lifecycle — state machine and registry */
ngx_anytls_stream_t *ngx_anytls_core_stream_create(
    ngx_anytls_connection_t *ac, uint32_t id);
ngx_anytls_stream_t *ngx_anytls_core_stream_find(
    ngx_anytls_connection_t *ac, uint32_t id);
ngx_uint_t ngx_anytls_core_stream_exists(
    ngx_anytls_connection_t *ac, uint32_t id);
void ngx_anytls_core_stream_close(ngx_anytls_stream_t *st);
void ngx_anytls_core_stream_mark_closed(ngx_anytls_stream_t *st);
ngx_int_t ngx_anytls_core_stream_send_fin(ngx_anytls_stream_t *st);


#endif
