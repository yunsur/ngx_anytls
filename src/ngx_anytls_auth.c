#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_auth.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_connection_private.h"


/*
 * Constant-time comparison for the client auth hash.
 *
 * The hash is the first thing a client sends on a public TLS port; a
 * data-dependent compare would leak password-hash information through
 * timing, so never use ngx_memcmp() here.
 */
static ngx_int_t
ngx_anytls_auth_hash_eq(const u_char *a, const u_char *b, size_t len)
{
    volatile u_char diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff == 0 ? NGX_OK : NGX_ERROR;
}


ngx_anytls_auth_step_t
ngx_anytls_auth_process(ngx_anytls_connection_t *ac, u_char *data, size_t len)
{
    ngx_anytls_auth_step_t result;
    size_t n, need;

    ngx_memzero(&result, sizeof(result));

    if (ac->auth_len < 34) {
        n = ngx_min(len, 34 - ac->auth_len);
        ngx_memcpy(ac->auth + ac->auth_len, data, n);
        ac->auth_len += n;
        result.consumed += n;
        data += n;
        len -= n;

        if (ac->auth_len < 34) {
            result.result = NGX_ANYTLS_AUTH_MORE;
            return result;
        }
    }

    if (ngx_anytls_auth_hash_eq(ac->auth, ac->conf->password_hash, 32)
        != NGX_OK)
    {
        if (len > 0) {
            n = ngx_min(len, sizeof(ac->auth) - ac->auth_len);
            ngx_memcpy(ac->auth + ac->auth_len, data, n);
            ac->auth_len += n;
            result.consumed += n;
        }

        result.result = NGX_ANYTLS_AUTH_FALLBACK;
        result.fallback_replay = ac->auth;
        result.fallback_replay_len = ac->auth_len;
        return result;
    }

    ac->auth_padding_len = (uint16_t) ((ac->auth[32] << 8) | ac->auth[33]);
    need = 34 + ac->auth_padding_len;
    if (need > sizeof(ac->auth)) {
        result.result = NGX_ANYTLS_AUTH_ERROR;
        return result;
    }

    if (ac->auth_len < need) {
        n = ngx_min(len, need - ac->auth_len);
        ngx_memcpy(ac->auth + ac->auth_len, data, n);
        ac->auth_len += n;
        result.consumed += n;

        if (ac->auth_len < need) {
            result.result = NGX_ANYTLS_AUTH_MORE;
            return result;
        }
    }

    ac->authenticated = 1;
    ac->state = NGX_ANYTLS_CONN_SETTINGS;
    result.result = NGX_ANYTLS_AUTH_OK;
    return result;
}
