#include "ngx_anytls_cache_budget.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define FUZZ_MAX_OBJECTS  64

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_anytls_cache_budget_t budget = { 0, 0 };
    size_t allocations[FUZZ_MAX_OBJECTS];
    size_t max_bytes, max_objects, allocation_size;
    size_t model_bytes, model_objects, old_bytes, old_objects;
    uint8_t control;
    int accepted, expected;

    if (size < 2) {
        return 0;
    }

    max_bytes = 1 + ((size_t) data[0] << 8) + data[1];
    max_objects = 1 + data[0] % FUZZ_MAX_OBJECTS;
    model_bytes = 0;
    model_objects = 0;
    data += 2;
    size -= 2;

    while (size != 0) {
        control = *data++;
        size--;

        if ((control & 1) != 0 && model_objects != 0) {
            allocation_size = allocations[model_objects - 1];
            ngx_anytls_cache_budget_remove(&budget, allocation_size);
            model_bytes -= allocation_size;
            model_objects--;

        } else {
            allocation_size = 1 + ((size_t) (control >> 1) << 8);
            if (size != 0) {
                allocation_size += *data++;
                size--;
            }

            old_bytes = budget.bytes;
            old_objects = budget.objects;
            expected = (model_objects < max_objects
                        && allocation_size <= max_bytes - model_bytes);
            accepted = ngx_anytls_cache_budget_add(&budget, allocation_size,
                                                    max_bytes, max_objects);
            if (accepted != expected) {
                abort();
            }
            if (accepted) {
                allocations[model_objects] = allocation_size;
                model_bytes += allocation_size;
                model_objects++;
            } else if (budget.bytes != old_bytes
                       || budget.objects != old_objects)
            {
                abort();
            }
        }

        if (budget.bytes != model_bytes
            || budget.objects != model_objects
            || budget.bytes > max_bytes
            || budget.objects > max_objects)
        {
            abort();
        }
    }

    while (model_objects != 0) {
        allocation_size = allocations[model_objects - 1];
        ngx_anytls_cache_budget_remove(&budget, allocation_size);
        model_objects--;
    }
    if (budget.bytes != 0 || budget.objects != 0) {
        abort();
    }

    return 0;
}
