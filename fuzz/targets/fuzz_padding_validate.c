#include "ngx_anytls_padding.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void) ngx_anytls_padding_validate((u_char *) data, size);
    return 0;
}
