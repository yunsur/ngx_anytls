#include "ngx_anytls_stream_index.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_MAX_STREAMS  128

typedef struct {
    uint32_t  id;
} fuzz_entry_t;

static void
rebuild_index(void ***slotsp, uint32_t *capacityp, size_t *tombstonesp,
    fuzz_entry_t *entries, const uint8_t *present, size_t max_streams,
    uint32_t target_capacity)
{
    void **slots;
    size_t i;

    slots = calloc(target_capacity, sizeof(*slots));
    if (slots == NULL) {
        abort();
    }

    for (i = 0; i < max_streams; i++) {
        if (present[i]
            && !ngx_anytls_stream_index_insert(slots, target_capacity - 1,
                                                &entries[i]))
        {
            abort();
        }
    }

    free(*slotsp);
    *slotsp = slots;
    *capacityp = target_capacity;
    *tombstonesp = 0;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_entry_t entries[FUZZ_MAX_STREAMS];
    uint8_t present[FUZZ_MAX_STREAMS] = { 0 };
    void **slots = NULL;
    size_t max_streams, active, tombstones, i, selected;
    uint32_t capacity, target_capacity, bucket;
    uint8_t control;

    if (size == 0) {
        return 0;
    }

    max_streams = 1 + data[0] % FUZZ_MAX_STREAMS;
    bucket = size > 1 ? data[1] : data[0];
    for (i = 0; i < max_streams; i++) {
        entries[i].id = bucket + (uint32_t) i * 256;
    }

    active = 0;
    tombstones = 0;
    capacity = 0;
    data++;
    size--;

    while (size != 0) {
        control = *data++;
        size--;
        selected = control % max_streams;

        switch (control >> 6) {
        case 0:
            if (present[selected]) {
                break;
            }
            if (ngx_anytls_stream_index_needs_rebuild(capacity, active,
                                                       tombstones))
            {
                target_capacity = ngx_anytls_stream_index_next_capacity(
                    capacity, active, max_streams);
                rebuild_index(&slots, &capacity, &tombstones, entries,
                              present, max_streams, target_capacity);
            }
            if (!ngx_anytls_stream_index_insert(slots, capacity - 1,
                                                 &entries[selected]))
            {
                abort();
            }
            present[selected] = 1;
            active++;
            break;

        case 1:
            if (!present[selected]) {
                break;
            }
            if (!ngx_anytls_stream_index_remove(slots, capacity - 1,
                                                 &entries[selected]))
            {
                abort();
            }
            present[selected] = 0;
            active--;
            tombstones++;
            if (active == 0) {
                if (capacity != NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY) {
                    rebuild_index(&slots, &capacity, &tombstones, entries,
                                  present, max_streams,
                                  NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY);
                } else {
                    memset(slots, 0, capacity * sizeof(*slots));
                    tombstones = 0;
                }
            } else if (tombstones >= 64 && tombstones > active) {
                rebuild_index(&slots, &capacity, &tombstones, entries,
                              present, max_streams, capacity);
            }
            break;

        case 2:
            if ((ngx_anytls_stream_index_find(slots, capacity - 1,
                                               entries[selected].id)
                 == &entries[selected]) != present[selected])
            {
                abort();
            }
            break;

        default:
            if (slots != NULL && tombstones != 0) {
                rebuild_index(&slots, &capacity, &tombstones, entries,
                              present, max_streams, capacity);
            }
            break;
        }

        if (active > max_streams
            || capacity > ngx_anytls_stream_index_max_capacity(max_streams)
            || (capacity != 0 && active > capacity / 2))
        {
            abort();
        }
    }

    for (i = 0; i < max_streams; i++) {
        if ((ngx_anytls_stream_index_find(slots, capacity - 1, entries[i].id)
             == &entries[i]) != present[i])
        {
            abort();
        }
    }

    free(slots);
    return 0;
}
