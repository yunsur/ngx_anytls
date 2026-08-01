#include "ngx_anytls_socksaddr.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t *pool;
    ngx_anytls_addr_t addr;
    u_char *payload;
    size_t payload_len, consumed;

    if (size > 65536) {
        return 0;
    }

    pool = ngx_create_pool(4096, NULL);
    if (pool == NULL) {
        return 0;
    }

    (void) ngx_anytls_parse_uot_packet(pool, (u_char *) data, size,
                                       &addr, &payload, &payload_len,
                                       &consumed);
    ngx_destroy_pool(pool);
    return 0;
}
