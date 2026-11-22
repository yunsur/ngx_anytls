#ifndef NGX_ANYTLS_STREAM_INDEX_H_INCLUDED
#define NGX_ANYTLS_STREAM_INDEX_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#define NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY  64U
#define NGX_ANYTLS_STREAM_INDEX_TOMBSTONE          ((void *) (uintptr_t) 1)

/*
 * Indexed values begin with their uint32_t stream id.  ngx_anytls_stream_t
 * keeps id as its first field; standalone tests use the same layout.
 */
static inline uint32_t
ngx_anytls_stream_index_id(const void *value)
{
    return *(const uint32_t *) value;
}


static inline uint32_t
ngx_anytls_stream_index_max_capacity(size_t max_streams)
{
    uint32_t capacity;

    capacity = NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY;
    while ((size_t) capacity / 2 < max_streams
           && capacity <= UINT32_MAX / 2)
    {
        capacity <<= 1;
    }

    return capacity;
}


static inline int
ngx_anytls_stream_index_needs_rebuild(uint32_t capacity, size_t active,
    size_t tombstones)
{
    size_t half;

    if (capacity == 0) {
        return 1;
    }

    half = capacity / 2;
    if (active >= half) {
        return 1;
    }

    return tombstones >= half - active;
}


static inline uint32_t
ngx_anytls_stream_index_next_capacity(uint32_t capacity, size_t active,
    size_t max_streams)
{
    uint32_t limit, next;

    if (capacity == 0) {
        return NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY;
    }
    if (active < capacity / 2) {
        return capacity;
    }

    limit = ngx_anytls_stream_index_max_capacity(max_streams);
    if (capacity >= limit || capacity > UINT32_MAX / 2) {
        return capacity;
    }

    next = capacity << 1;
    return next < limit ? next : limit;
}


static inline void *
ngx_anytls_stream_index_find(void **slots, uint32_t mask, uint32_t id)
{
    void *entry;
    uint32_t i, index;

    if (slots == NULL) {
        return NULL;
    }

    index = id & mask;
    for (i = 0; i <= mask; i++) {
        entry = slots[index];
        if (entry == NULL) {
            return NULL;
        }
        if (entry != NGX_ANYTLS_STREAM_INDEX_TOMBSTONE
            && ngx_anytls_stream_index_id(entry) == id)
        {
            return entry;
        }
        index = (index + 1) & mask;
    }

    return NULL;
}


static inline int
ngx_anytls_stream_index_insert(void **slots, uint32_t mask, void *value)
{
    uint32_t i, index;

    index = ngx_anytls_stream_index_id(value) & mask;
    for (i = 0; i <= mask; i++) {
        if (slots[index] == NULL
            || slots[index] == NGX_ANYTLS_STREAM_INDEX_TOMBSTONE)
        {
            slots[index] = value;
            return 1;
        }
        index = (index + 1) & mask;
    }

    return 0;
}


static inline int
ngx_anytls_stream_index_remove(void **slots, uint32_t mask, void *value)
{
    uint32_t i, index;

    index = ngx_anytls_stream_index_id(value) & mask;
    for (i = 0; i <= mask; i++) {
        if (slots[index] == value) {
            slots[index] = NGX_ANYTLS_STREAM_INDEX_TOMBSTONE;
            return 1;
        }
        if (slots[index] == NULL) {
            return 0;
        }
        index = (index + 1) & mask;
    }

    return 0;
}

#endif /* NGX_ANYTLS_STREAM_INDEX_H_INCLUDED */
