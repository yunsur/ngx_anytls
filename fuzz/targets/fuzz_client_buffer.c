#include "ngx_anytls_client_buffer.h"
#include "ngx_anytls_protocol.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_anytls_client_buffer_t buffer;
    ngx_anytls_frame_t frame;
    ngx_uint_t authenticated;
    size_t consumed, copied, chunk, available;
    uint8_t control;

    if (size == 0) {
        return 0;
    }

    ngx_memzero(&buffer, sizeof(buffer));
    if (ngx_anytls_client_buffer_init(&buffer, NULL) != NGX_OK) {
        return 0;
    }

    authenticated = data[0] & 1;
    data++;
    size--;

    while (size != 0) {
        control = *data++;
        size--;
        chunk = 1 + (control >> 1);
        if (chunk > size) {
            chunk = size;
        }

        if (ngx_anytls_client_buffer_prepare(&buffer, authenticated, NULL)
            != NGX_OK)
        {
            break;
        }

        available = buffer.capacity - buffer.remnant_len;
        copied = ngx_min(chunk, available);
        if (copied != 0) {
            ngx_memcpy(buffer.data + buffer.remnant_len, data, copied);
            buffer.remnant_len += copied;
            data += copied;
            size -= copied;
        }

        if (ngx_anytls_client_buffer_prepare(&buffer, authenticated, NULL)
            != NGX_OK)
        {
            break;
        }

        if (authenticated) {
            while (ngx_anytls_parse_frame(
                       buffer.data, buffer.data + buffer.remnant_len,
                       &frame, &consumed) == NGX_OK)
            {
                buffer.remnant_len -= consumed;
                if (buffer.remnant_len != 0) {
                    ngx_memmove(buffer.data, buffer.data + consumed,
                                buffer.remnant_len);
                }
            }
        }

        ngx_anytls_client_buffer_release_oversized(&buffer);

        if (copied == 0 && available == 0) {
            break;
        }
    }

    ngx_anytls_client_buffer_destroy(&buffer);
    return 0;
}
