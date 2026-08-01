#include "ngx_anytls_protocol.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_anytls_frame_t frame;
    size_t consumed = 0;

    (void) ngx_anytls_parse_frame((u_char *) data, (u_char *) data + size,
                                  &frame, &consumed);
    return 0;
}
