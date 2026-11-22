#include "ngx_anytls_client_buffer.h"
#include "ngx_anytls_protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_anytls_client_buffer_t buffer;
    ngx_anytls_frame_t frame;
    ngx_uint_t authenticated, active_streams;
    size_t consumed, copied, chunk, available;
    uint8_t control;

    if (size == 0) {
        return 0;
    }

    ngx_memzero(&buffer, sizeof(buffer));
    ngx_anytls_client_buffer_init(&buffer);

    authenticated = data[0] & 1;
    data++;
    size--;

    while (size != 0) {
        control = *data++;
        size--;
        active_streams = (control >> 1) & 1;
        chunk = 1 + (control >> 2);
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

        ngx_anytls_client_buffer_release_if_idle(&buffer, active_streams);
        if (active_streams == 0 && buffer.remnant_len == 0
            && (buffer.data != NULL || buffer.capacity != 0))
        {
            abort();
        }
        if (active_streams != 0 && buffer.data == NULL) {
            abort();
        }

        if (copied == 0 && available == 0) {
            break;
        }
    }

    ngx_anytls_client_buffer_destroy(&buffer);
    return 0;
}
