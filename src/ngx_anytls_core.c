#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_anytls_core.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_padding.h"
#include "ngx_anytls_socksaddr.h"
#include <openssl/sha.h>


/* Core implementation — delegates to existing protocol helpers.
 *
 * This file establishes the canonical core API.  In a future step,
 * the underlying protocol/padding/socksaddr files can be merged
 * into this file or kept separate; the key boundary is that callers
 * outside core/ should go through ngx_anytls_core_*.
 */


ngx_int_t
ngx_anytls_core_parse_frame(u_char *pos, u_char *last,
    ngx_anytls_frame_t *frame, size_t *consumed)
{
    return ngx_anytls_parse_frame(pos, last, frame, consumed);
}


u_char *
ngx_anytls_core_write_frame_header(u_char *p, ngx_uint_t cmd,
    uint32_t stream_id, uint16_t len)
{
    return ngx_anytls_write_frame_header(p, cmd, stream_id, len);
}


ngx_int_t
ngx_anytls_core_validate_padding(u_char *data, size_t len)
{
    return ngx_anytls_padding_validate(data, len);
}


ngx_int_t
ngx_anytls_core_parse_socksaddr(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_addr_t *addr)
{
    return ngx_anytls_parse_socksaddr(pool, data, len, addr);
}


void
ngx_anytls_core_sha256(ngx_str_t *password, u_char out[32])
{
    ngx_anytls_sha256(password, out);
}


ngx_int_t
ngx_anytls_core_parse_settings(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_settings_t *settings)
{
    return ngx_anytls_parse_settings(pool, data, len, settings);
}


const char *
ngx_anytls_core_cmd_name(ngx_uint_t cmd)
{
    return ngx_anytls_cmd_name(cmd);
}


ngx_int_t
ngx_anytls_core_parse_uot_packet(ngx_pool_t *pool, u_char *data,
    size_t len, ngx_anytls_addr_t *addr, u_char **payload,
    size_t *payload_len, size_t *consumed)
{
    return ngx_anytls_parse_uot_packet(pool, data, len, addr, payload,
                                       payload_len, consumed);
}
