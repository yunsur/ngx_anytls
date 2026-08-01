#include "test_helpers.h"
#include "ngx_anytls_padding.h"

static const u_char default_scheme[] =
    "stop=8\n"
    "0=30-30\n"
    "1=100-400\n"
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
    "3=9-9,500-1000\n"
    "4=500-1000\n"
    "5=500-1000\n"
    "6=500-1000\n"
    "7=500-1000\n";

static void
test_default_scheme(void)
{
    ASSERT_EQ(ngx_anytls_padding_validate((u_char *) default_scheme,
                                          sizeof(default_scheme) - 1), NGX_OK);
}

static void
test_minimal_scheme(void)
{
    u_char data[] = "stop=1\n";

    ASSERT_EQ(ngx_anytls_padding_validate(data, sizeof(data) - 1), NGX_OK);
}

static void
test_missing_stop_rejected(void)
{
    u_char data[] = "0=30-30\n";

    ASSERT_EQ(ngx_anytls_padding_validate(data, sizeof(data) - 1), NGX_ERROR);
}

static void
test_empty_rejected(void)
{
    ASSERT_EQ(ngx_anytls_padding_validate((u_char *) "", 0), NGX_ERROR);
}

static void
test_comments_accepted(void)
{
    u_char data[] = "# comment\nstop=2\n# another\n0=10-10\n";

    ASSERT_EQ(ngx_anytls_padding_validate(data, sizeof(data) - 1), NGX_OK);
}

static void
test_crlf_accepted(void)
{
    u_char data[] = "stop=1\r\n0=10-10\r\n";

    ASSERT_EQ(ngx_anytls_padding_validate(data, sizeof(data) - 1), NGX_OK);
}

static void
test_garbage_rejected(void)
{
    u_char data[] = "\x00\x01\x02===not a padding";

    ASSERT_EQ(ngx_anytls_padding_validate(data, sizeof(data) - 1), NGX_ERROR);
}

static void
test_null_rejected(void)
{
    ASSERT_EQ(ngx_anytls_padding_validate(NULL, 10), NGX_ERROR);
}

static void
run_all_tests(void)
{
    test_default_scheme();
    test_minimal_scheme();
    test_missing_stop_rejected();
    test_empty_rejected();
    test_comments_accepted();
    test_crlf_accepted();
    test_garbage_rejected();
    test_null_rejected();
}

TEST_MAIN()
