#include "ngx_anytls_protocol.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t *pool;
    ngx_anytls_settings_t settings;

    if (size > 65536) {
        return 0;
    }

    pool = ngx_create_pool(4096, NULL);
    if (pool == NULL) {
        return 0;
    }

    (void) ngx_anytls_parse_settings(pool, (u_char *) data, size, &settings);
    ngx_destroy_pool(pool);
    return 0;
}
