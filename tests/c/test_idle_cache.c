#include "ngx_anytls_idle_cache.h"

#include <stdio.h>

static int tests_run;
static int tests_failed;

#define ASSERT_EQ(actual, expected)                                         \
    do {                                                                    \
        int _actual = (int) (actual);                                       \
        int _expected = (int) (expected);                                   \
        tests_run++;                                                        \
        if (_actual != _expected) {                                         \
            tests_failed++;                                                \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%d != %d)\n",            \
                    __FILE__, __LINE__, #actual, #expected,                  \
                    _actual, _expected);                                    \
        }                                                                   \
    } while (0)

static void
test_trim_eligibility(void)
{
    ASSERT_EQ(ngx_anytls_idle_cache_eligible(0, 0, 0, 0, 0), 1);
    ASSERT_EQ(ngx_anytls_idle_cache_eligible(1, 0, 0, 0, 0), 0);
    ASSERT_EQ(ngx_anytls_idle_cache_eligible(0, 1, 0, 0, 0), 0);
    ASSERT_EQ(ngx_anytls_idle_cache_eligible(0, 0, 1, 0, 0), 0);
    ASSERT_EQ(ngx_anytls_idle_cache_eligible(0, 0, 0, 1, 0), 0);
    ASSERT_EQ(ngx_anytls_idle_cache_eligible(0, 0, 0, 0, 1), 0);
}


static void
test_grace_period_lifecycle(void)
{
    ngx_anytls_idle_cache_policy_t policy = { 0 };

    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_OPEN);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_CHECK, 0),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_CHECK, 1),
        NGX_ANYTLS_IDLE_CACHE_ARM);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_ARMED);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_CHECK, 1),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_ACTIVITY, 0),
        NGX_ANYTLS_IDLE_CACHE_CANCEL);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_OPEN);

    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_CHECK, 1),
        NGX_ANYTLS_IDLE_CACHE_ARM);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_TIMER, 0),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_OPEN);

    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_CHECK, 1),
        NGX_ANYTLS_IDLE_CACHE_ARM);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_TIMER, 1),
        NGX_ANYTLS_IDLE_CACHE_TRIM);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_OPEN);
}


static void
test_output_drain_rearms_after_ineligible_timer(void)
{
    ngx_anytls_idle_cache_policy_t policy = { 0 };

    ASSERT_EQ(
        ngx_anytls_idle_cache_recheck(&policy, 0, 0, 7, 1, 0),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_OPEN);
    ASSERT_EQ(
        ngx_anytls_idle_cache_recheck(&policy, 0, 0, 0, 0, 0),
        NGX_ANYTLS_IDLE_CACHE_ARM);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_TIMER, 0),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_OPEN);
    ASSERT_EQ(
        ngx_anytls_idle_cache_recheck(&policy, 0, 0, 0, 0, 0),
        NGX_ANYTLS_IDLE_CACHE_ARM);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_TIMER, 1),
        NGX_ANYTLS_IDLE_CACHE_TRIM);
}


static void
test_finalize_is_absorbing(void)
{
    ngx_anytls_idle_cache_policy_t policy = { 0 };

    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_CHECK, 1),
        NGX_ANYTLS_IDLE_CACHE_ARM);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_FINALIZE, 0),
        NGX_ANYTLS_IDLE_CACHE_CANCEL);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_CLOSED);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_CHECK, 1),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_ACTIVITY, 0),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_TIMER, 1),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(
        ngx_anytls_idle_cache_transition(
            &policy, NGX_ANYTLS_IDLE_CACHE_FINALIZE, 0),
        NGX_ANYTLS_IDLE_CACHE_NONE);
    ASSERT_EQ(policy.state, NGX_ANYTLS_IDLE_CACHE_CLOSED);
}


int
main(void)
{
    test_trim_eligibility();
    test_grace_period_lifecycle();
    test_output_drain_rearms_after_ineligible_timer();
    test_finalize_is_absorbing();

    if (tests_failed != 0) {
        fprintf(stderr, "FAILED: %d/%d assertions\n", tests_failed, tests_run);
        return 1;
    }

    printf("PASS: %d assertions\n", tests_run);
    return 0;
}
