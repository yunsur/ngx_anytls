#ifndef NGX_ANYTLS_TEST_HELPERS_H_INCLUDED
#define NGX_ANYTLS_TEST_HELPERS_H_INCLUDED

/* Module headers require nginx platform setup first. */
#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_failed = 0;

#define ASSERT(cond)                                                          \
    do {                                                                      \
        tests_run++;                                                          \
        if (!(cond)) {                                                        \
            tests_failed++;                                                   \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                                     \
    } while (0)

#define ASSERT_EQ(a, b)                                                       \
    do {                                                                      \
        long long _a = (long long) (a);                                       \
        long long _b = (long long) (b);                                       \
        tests_run++;                                                          \
        if (_a != _b) {                                                       \
            tests_failed++;                                                   \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%lld != %lld)\n",          \
                    __FILE__, __LINE__, #a, #b, _a, _b);                      \
        }                                                                     \
    } while (0)

#define ASSERT_MEM(a, b, n)                                                   \
    do {                                                                      \
        tests_run++;                                                          \
        if (memcmp((a), (b), (n)) != 0) {                                     \
            tests_failed++;                                                   \
            fprintf(stderr, "FAIL %s:%d: %s != %s (%u bytes)\n",              \
                    __FILE__, __LINE__, #a, #b, (unsigned) (n));              \
        }                                                                     \
    } while (0)

#define ASSERT_NOTNULL(p) ASSERT((p) != NULL)
#define ASSERT_NULL(p)    ASSERT((p) == NULL)

#define TEST_MAIN()                                                           \
int                                                                            \
main(void)                                                                     \
{                                                                              \
    run_all_tests();                                                           \
    if (tests_failed) {                                                        \
        fprintf(stderr, "FAILED: %d/%d assertions\n",                          \
                tests_failed, tests_run);                                      \
        return 1;                                                              \
    }                                                                          \
    printf("PASS: %d assertions\n", tests_run);                                \
    return 0;                                                                  \
}

#endif /* NGX_ANYTLS_TEST_HELPERS_H_INCLUDED */
