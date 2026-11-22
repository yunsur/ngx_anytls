#include "ngx_anytls_cache_budget.h"

#include <stdint.h>
#include <stdio.h>

#define TEST_CACHE_BYTES    (64 * 1024)
#define TEST_CACHE_OBJECTS  64

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

static void
test_object_limit_bounds_tiny_allocations(void)
{
    ngx_anytls_cache_budget_t budget = { 0, 0 };
    size_t allocation_size = 17;
    size_t i;

    for (i = 0; i < TEST_CACHE_OBJECTS; i++) {
        ASSERT(ngx_anytls_cache_budget_add(&budget, allocation_size,
                                           TEST_CACHE_BYTES,
                                           TEST_CACHE_OBJECTS));
    }

    ASSERT_EQ(budget.bytes, 1088);
    ASSERT_EQ(budget.objects, TEST_CACHE_OBJECTS);
    ASSERT(!ngx_anytls_cache_budget_add(&budget, allocation_size,
                                        TEST_CACHE_BYTES,
                                        TEST_CACHE_OBJECTS));
    ASSERT_EQ(budget.bytes, 1088);
    ASSERT_EQ(budget.objects, TEST_CACHE_OBJECTS);

    ngx_anytls_cache_budget_remove(&budget, allocation_size);
    ASSERT_EQ(budget.bytes, 1071);
    ASSERT_EQ(budget.objects, TEST_CACHE_OBJECTS - 1);
    ASSERT(ngx_anytls_cache_budget_add(&budget, allocation_size,
                                       TEST_CACHE_BYTES,
                                       TEST_CACHE_OBJECTS));
}


static void
test_true_allocation_bytes_bound_cache(void)
{
    ngx_anytls_cache_budget_t budget = { 0, 0 };
    size_t allocation_size = 16 + 16384;

    ASSERT(ngx_anytls_cache_budget_add(&budget, allocation_size,
                                       TEST_CACHE_BYTES,
                                       TEST_CACHE_OBJECTS));
    ASSERT(ngx_anytls_cache_budget_add(&budget, allocation_size,
                                       TEST_CACHE_BYTES,
                                       TEST_CACHE_OBJECTS));
    ASSERT(ngx_anytls_cache_budget_add(&budget, allocation_size,
                                       TEST_CACHE_BYTES,
                                       TEST_CACHE_OBJECTS));
    ASSERT(!ngx_anytls_cache_budget_add(&budget, allocation_size,
                                        TEST_CACHE_BYTES,
                                        TEST_CACHE_OBJECTS));
    ASSERT_EQ(budget.bytes, 49200);
    ASSERT_EQ(budget.objects, 3);
}


static void
test_overflow_and_underflow_are_bounded(void)
{
    ngx_anytls_cache_budget_t budget = { SIZE_MAX, 1 };

    ASSERT(!ngx_anytls_cache_budget_add(&budget, 1, SIZE_MAX, 2));
    ASSERT_EQ(budget.bytes, SIZE_MAX);
    ASSERT_EQ(budget.objects, 1);

    ngx_anytls_cache_budget_remove(&budget, SIZE_MAX);
    ASSERT_EQ(budget.bytes, 0);
    ASSERT_EQ(budget.objects, 0);
    ngx_anytls_cache_budget_remove(&budget, 1);
    ASSERT_EQ(budget.bytes, 0);
    ASSERT_EQ(budget.objects, 0);
}


int
main(void)
{
    test_object_limit_bounds_tiny_allocations();
    test_true_allocation_bytes_bound_cache();
    test_overflow_and_underflow_are_bounded();

    if (tests_failed != 0) {
        fprintf(stderr, "FAILED: %d/%d assertions\n",
                tests_failed, tests_run);
        return 1;
    }

    printf("PASS: %d assertions\n", tests_run);
    return 0;
}
