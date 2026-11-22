#include "ngx_anytls_stream_index.h"

#include <stdio.h>
#include <stdlib.h>

#define TEST_MAX_STREAMS  128

static int tests_run;
static int tests_failed;

#define ASSERT(condition)                                                   \
    do {                                                                    \
        tests_run++;                                                        \
        if (!(condition)) {                                                 \
            tests_failed++;                                                \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,         \
                    #condition);                                            \
        }                                                                   \
    } while (0)

#define ASSERT_EQ(actual, expected)                                         \
    do {                                                                    \
        size_t _actual = (size_t) (actual);                                 \
        size_t _expected = (size_t) (expected);                             \
        tests_run++;                                                        \
        if (_actual != _expected) {                                         \
            tests_failed++;                                                \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%zu != %zu)\n",          \
                    __FILE__, __LINE__, #actual, #expected,                  \
                    _actual, _expected);                                    \
        }                                                                   \
    } while (0)

typedef struct {
    uint32_t  id;
} test_entry_t;

static void
test_capacity_policy(void)
{
    ASSERT_EQ(ngx_anytls_stream_index_max_capacity(1), 64);
    ASSERT_EQ(ngx_anytls_stream_index_max_capacity(32), 64);
    ASSERT_EQ(ngx_anytls_stream_index_max_capacity(33), 128);
    ASSERT_EQ(ngx_anytls_stream_index_max_capacity(1024), 2048);
    ASSERT_EQ(ngx_anytls_stream_index_max_capacity(65536), 131072);

    ASSERT(!ngx_anytls_stream_index_needs_rebuild(64, 31, 0));
    ASSERT(ngx_anytls_stream_index_needs_rebuild(64, 32, 0));
    ASSERT_EQ(ngx_anytls_stream_index_next_capacity(64, 31,
                                                     TEST_MAX_STREAMS), 64);
    ASSERT_EQ(ngx_anytls_stream_index_next_capacity(64, 32,
                                                     TEST_MAX_STREAMS), 128);
    ASSERT_EQ(ngx_anytls_stream_index_next_capacity(128, 64,
                                                     TEST_MAX_STREAMS), 256);
    ASSERT_EQ(ngx_anytls_stream_index_next_capacity(256, 128,
                                                     TEST_MAX_STREAMS), 256);
}


static void
test_collision_removal_and_compaction(void)
{
    void *slots[NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY] = { 0 };
    void *compacted[NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY] = { 0 };
    test_entry_t entries[48];
    size_t i;

    for (i = 0; i < 32; i++) {
        entries[i].id = 1 + (uint32_t) i * 64;
        ASSERT(ngx_anytls_stream_index_insert(slots, 63, &entries[i]));
    }
    for (i = 0; i < 32; i++) {
        ASSERT(ngx_anytls_stream_index_find(slots, 63, entries[i].id)
               == &entries[i]);
    }

    for (i = 0; i < 16; i++) {
        ASSERT(ngx_anytls_stream_index_remove(slots, 63, &entries[i]));
        ASSERT(ngx_anytls_stream_index_find(slots, 63, entries[i].id)
               == NULL);
    }
    ASSERT(ngx_anytls_stream_index_needs_rebuild(64, 16, 16));
    ASSERT_EQ(ngx_anytls_stream_index_next_capacity(64, 16,
                                                     TEST_MAX_STREAMS), 64);

    for (i = 16; i < 32; i++) {
        ASSERT(ngx_anytls_stream_index_insert(compacted, 63, &entries[i]));
    }
    for (i = 32; i < 48; i++) {
        entries[i].id = 1 + (uint32_t) i * 64;
        ASSERT(ngx_anytls_stream_index_insert(compacted, 63, &entries[i]));
    }
    for (i = 16; i < 48; i++) {
        ASSERT(ngx_anytls_stream_index_find(compacted, 63, entries[i].id)
               == &entries[i]);
    }

    for (i = 16; i < 48; i++) {
        ASSERT(ngx_anytls_stream_index_remove(compacted, 63, &entries[i]));
    }
    ASSERT(!ngx_anytls_stream_index_remove(compacted, 63, &entries[47]));
    ASSERT_EQ(NGX_ANYTLS_STREAM_INDEX_INITIAL_CAPACITY, 64);
}


int
main(void)
{
    test_capacity_policy();
    test_collision_removal_and_compaction();

    if (tests_failed != 0) {
        fprintf(stderr, "FAILED: %d/%d assertions\n",
                tests_failed, tests_run);
        return 1;
    }

    printf("PASS: %d assertions\n", tests_run);
    return 0;
}
