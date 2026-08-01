#include "test_helpers.h"
#include "ngx_anytls_protocol.h"

static ngx_pool_t *pool;

static void
test_version_only(void)
{
    ngx_anytls_settings_t s;
    u_char data[] = "v=2\n";

    ASSERT_EQ(ngx_anytls_parse_settings(pool, data, sizeof(data) - 1, &s),
              NGX_OK);
    ASSERT_EQ(s.version, 2u);
}

static void
test_client_and_padding_md5(void)
{
    ngx_anytls_settings_t s;
    u_char data[] = "client=my-app\npadding-md5=abc123\n";

    ASSERT_EQ(ngx_anytls_parse_settings(pool, data, sizeof(data) - 1, &s),
              NGX_OK);
    ASSERT_EQ(s.client.len, sizeof("my-app") - 1);
    ASSERT_MEM(s.client.data, "my-app", sizeof("my-app") - 1);
    ASSERT_EQ(s.padding_md5.len, sizeof("abc123") - 1);
    ASSERT_MEM(s.padding_md5.data, "abc123", sizeof("abc123") - 1);
}

static void
test_invalid_version_falls_back(void)
{
    ngx_anytls_settings_t s;
    u_char data[] = "v=not-a-number\n";

    ASSERT_EQ(ngx_anytls_parse_settings(pool, data, sizeof(data) - 1, &s),
              NGX_OK);
    ASSERT_EQ(s.version, 1u);
}

static void
test_crlf_and_empty_lines(void)
{
    ngx_anytls_settings_t s;
    u_char data[] = "\r\nv=2\r\n\nclient=x\r\n";

    ASSERT_EQ(ngx_anytls_parse_settings(pool, data, sizeof(data) - 1, &s),
              NGX_OK);
    ASSERT_EQ(s.version, 2u);
    ASSERT_EQ(s.client.len, sizeof("x") - 1);
}

static void
test_lines_without_equals_skipped(void)
{
    ngx_anytls_settings_t s;
    u_char data[] = "garbage line\nv=2\n";

    ASSERT_EQ(ngx_anytls_parse_settings(pool, data, sizeof(data) - 1, &s),
              NGX_OK);
    ASSERT_EQ(s.version, 2u);
}

static void
test_empty_input(void)
{
    ngx_anytls_settings_t s;

    ASSERT_EQ(ngx_anytls_parse_settings(pool, (u_char *) "", 0, &s), NGX_OK);
    ASSERT_EQ(s.version, 1u);
}

static void
run_all_tests(void)
{
    pool = ngx_create_pool(4096, NULL);
    ASSERT_NOTNULL(pool);

    test_version_only();
    test_client_and_padding_md5();
    test_invalid_version_falls_back();
    test_crlf_and_empty_lines();
    test_lines_without_equals_skipped();
    test_empty_input();

    ngx_destroy_pool(pool);
}

TEST_MAIN()
