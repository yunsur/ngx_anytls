#include "ngx_anytls_auth.h"
#include "ngx_anytls_connection_private.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static u_char fuzz_password_hash[32] = {
    0x5e, 0x88, 0x48, 0x98, 0xda, 0x28, 0x04, 0x71,
    0x51, 0xd0, 0xe5, 0x6f, 0x8d, 0xc6, 0x29, 0x27,
    0x73, 0x60, 0x3d, 0x0d, 0x6a, 0xab, 0xbd, 0xd6,
    0x2a, 0x11, 0xef, 0x72, 0x1d, 0x15, 0x42, 0xd8
};

static ngx_anytls_auth_step_t
fuzz_auth_run(const uint8_t *data, size_t size, ngx_uint_t fragmented)
{
    ngx_pool_t *pool;
    ngx_anytls_connection_t *ac;
    ngx_stream_anytls_srv_conf_t *conf;
    ngx_anytls_auth_step_t step;
    size_t n, off;

    step.result = NGX_ANYTLS_AUTH_ERROR;
    step.consumed = 0;
    step.fallback_replay = NULL;
    step.fallback_replay_len = 0;

    pool = ngx_create_pool(8192, NULL);
    if (pool == NULL) {
        return step;
    }

    ac = ngx_pcalloc(pool, sizeof(*ac));
    conf = ngx_pcalloc(pool, sizeof(*conf));

    if (ac == NULL || conf == NULL) {
        ngx_destroy_pool(pool);
        return step;
    }

    conf->users = ngx_pcalloc(pool, sizeof(ngx_anytls_user_t));
    if (conf->users == NULL) {
        ngx_destroy_pool(pool);
        return step;
    }
    conf->users_n = 1;
    ngx_memcpy(conf->users[0].hash, fuzz_password_hash, 32);
    ac->conf = conf;

    step.result = NGX_ANYTLS_AUTH_MORE;
    if (!fragmented || size == 0) {
        step = ngx_anytls_auth_process(ac, (u_char *) data, size);
    } else {
        for (off = 0; off < size && step.result == NGX_ANYTLS_AUTH_MORE;
             off += n)
        {
            n = size <= 512 ? 1 : 1 + data[off] % 64;
            if (n > size - off) {
                n = size - off;
            }
            step = ngx_anytls_auth_process(ac, (u_char *) data + off, n);
        }
    }

    if (step.result == NGX_ANYTLS_AUTH_FALLBACK
        && (step.fallback_replay_len != NGX_ANYTLS_AUTH_PREFIX_LEN
            || size < NGX_ANYTLS_AUTH_PREFIX_LEN
            || memcmp(step.fallback_replay, data,
                      NGX_ANYTLS_AUTH_PREFIX_LEN) != 0))
    {
        abort();
    }
    step.fallback_replay = NULL;
    ngx_destroy_pool(pool);
    return step;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_anytls_auth_step_t whole, fragmented;

    if (size > 65536) {
        return 0;
    }

    whole = fuzz_auth_run(data, size, 0);
    fragmented = fuzz_auth_run(data, size, 1);

    if (whole.result != fragmented.result
        || whole.fallback_replay_len != fragmented.fallback_replay_len)
    {
        abort();
    }

    return 0;
}
