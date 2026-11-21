#include "ngx_anytls_socksaddr.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t *pool;
    ngx_anytls_addr_t owned_addr, ref_addr;
    u_char *owned_payload, *ref_payload, *copy;
    size_t owned_payload_len, ref_payload_len;
    size_t owned_consumed, ref_consumed;
    ngx_int_t owned_rc, ref_rc;

    if (size > 65536) {
        return 0;
    }

    pool = ngx_create_pool(4096, NULL);
    if (pool == NULL) {
        return 0;
    }

    copy = malloc(size == 0 ? 1 : size);
    if (copy == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }
    if (size != 0) {
        memcpy(copy, data, size);
    }

    owned_rc = ngx_anytls_parse_uot_packet(pool, copy, size,
                                           &owned_addr, &owned_payload,
                                           &owned_payload_len,
                                           &owned_consumed);
    ref_rc = ngx_anytls_parse_uot_packet_ref((u_char *) data, size,
                                             &ref_addr, &ref_payload,
                                             &ref_payload_len,
                                             &ref_consumed);

    if (owned_rc != ref_rc) {
        abort();
    }
    if (owned_rc == NGX_OK
        && (owned_addr.atyp != ref_addr.atyp
            || owned_addr.port != ref_addr.port
            || owned_addr.mode != ref_addr.mode
            || owned_addr.host.len != ref_addr.host.len
            || owned_payload_len != ref_payload_len
            || owned_consumed != ref_consumed
            || memcmp(owned_addr.host.data, ref_addr.host.data,
                      owned_addr.host.len) != 0
            || memcmp(owned_payload, ref_payload, owned_payload_len) != 0))
    {
        abort();
    }

    free(copy);
    ngx_destroy_pool(pool);
    return 0;
}
