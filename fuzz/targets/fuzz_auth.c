#include "ngx_anytls_auth.h"
#include "ngx_anytls_connection_private.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static u_char fuzz_password_hash[32] = {
    0x5e, 0x88, 0x48, 0x98, 0xda, 0x28, 0x04, 0x71,
    0x51, 0xd0, 0xe5, 0x6f, 0x8d, 0xc6, 0x29, 0x27,
    0x73, 0x60, 0x3d, 0x0d, 0x6a, 0xab, 0xbd, 0xd6,
    0x2a, 0x11, 0xef, 0x72, 0x1d, 0x15, 0x42, 0xd8
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t *pool;
    ngx_anytls_connection_t *ac;
    ngx_stream_anytls_srv_conf_t *conf;

    if (size > 65536) {
        return 0;
    }

    pool = ngx_create_pool(8192, NULL);
    if (pool == NULL) {
        return 0;
    }

    ac = ngx_pcalloc(pool, sizeof(*ac));
    conf = ngx_pcalloc(pool, sizeof(*conf));

    if (ac == NULL || conf == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }

    ngx_memcpy(conf->password_hash, fuzz_password_hash, 32);
    conf->password_set = 1;
    ac->conf = conf;

    (void) ngx_anytls_auth_process(ac, (u_char *) data, size);
    ngx_destroy_pool(pool);
    return 0;
}
