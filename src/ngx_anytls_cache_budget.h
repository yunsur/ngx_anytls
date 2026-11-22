#ifndef NGX_ANYTLS_CACHE_BUDGET_H_INCLUDED
#define NGX_ANYTLS_CACHE_BUDGET_H_INCLUDED

#include <stddef.h>

typedef struct {
    size_t  bytes;
    size_t  objects;
} ngx_anytls_cache_budget_t;

static inline int
ngx_anytls_cache_budget_add(ngx_anytls_cache_budget_t *budget,
    size_t allocation_size, size_t max_bytes, size_t max_objects)
{
    if (allocation_size > max_bytes
        || budget->bytes > max_bytes - allocation_size
        || budget->objects >= max_objects)
    {
        return 0;
    }

    budget->bytes += allocation_size;
    budget->objects++;
    return 1;
}


static inline void
ngx_anytls_cache_budget_remove(ngx_anytls_cache_budget_t *budget,
    size_t allocation_size)
{
    if (budget->bytes >= allocation_size) {
        budget->bytes -= allocation_size;
    } else {
        budget->bytes = 0;
    }

    if (budget->objects != 0) {
        budget->objects--;
    }
}

#endif /* NGX_ANYTLS_CACHE_BUDGET_H_INCLUDED */
