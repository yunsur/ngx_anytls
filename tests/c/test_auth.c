#include "test_helpers.h"
#include "ngx_anytls_auth.h"
#include "ngx_anytls_connection_private.h"

static u_char fuzz_password_hash[32] = {
    0x5e, 0x88, 0x48, 0x98, 0xda, 0x28, 0x04, 0x71,
    0x51, 0xd0, 0xe5, 0x6f, 0x8d, 0xc6, 0x29, 0x27,
    0x73, 0x60, 0x3d, 0x0d, 0x6a, 0xab, 0xbd, 0xd6,
    0x2a, 0x11, 0xef, 0x72, 0x1d, 0x15, 0x42, 0xd8
};

static ngx_pool_t *pool;
static ngx_anytls_connection_t *ac;

static void
set_up(void)
{
    ngx_stream_anytls_srv_conf_t *conf;

    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }

    pool = ngx_create_pool(8192, NULL);
    ac = ngx_pcalloc(pool, sizeof(*ac));
    conf = ngx_pcalloc(pool, sizeof(*conf));

    conf->users = ngx_pcalloc(pool, sizeof(ngx_anytls_user_t));
    conf->users_n = 1;
    conf->users[0].name.len = 8;
    conf->users[0].name.data = (u_char *) "test-user";
    memcpy(conf->users[0].hash, fuzz_password_hash, 32);
    ac->conf = conf;
}

static void
test_ok_no_padding(void)
{
    u_char data[34];
    ngx_anytls_auth_step_t r;

    memcpy(data, fuzz_password_hash, 32);
    data[32] = 0;
    data[33] = 0;

    r = ngx_anytls_auth_process(ac, data, sizeof(data));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_OK);
    ASSERT_EQ(r.consumed, sizeof(data));

    /* matching named user is recorded on the connection */
    ASSERT_EQ((int) ac->user_name.len, 8);
    ASSERT_MEM(ac->user_name.data, "test-user", 8);
}

static void
test_ok_with_padding(void)
{
    u_char data[34 + 3];
    ngx_anytls_auth_step_t r;

    memcpy(data, fuzz_password_hash, 32);
    data[32] = 0;
    data[33] = 3;
    memcpy(data + 34, "abc", 3);

    r = ngx_anytls_auth_process(ac, data, sizeof(data));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_OK);
    ASSERT_EQ(r.consumed, sizeof(data));
}

static void
test_partial_input_more(void)
{
    u_char data[16];
    ngx_anytls_auth_step_t r;

    memcpy(data, fuzz_password_hash, 16);
    r = ngx_anytls_auth_process(ac, data, sizeof(data));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);
}

static void
test_split_accumulation(void)
{
    u_char data[34];
    ngx_anytls_auth_step_t r;

    memcpy(data, fuzz_password_hash, 32);
    data[32] = 0;
    data[33] = 0;

    r = ngx_anytls_auth_process(ac, data, 20);
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);

    r = ngx_anytls_auth_process(ac, data + 20, sizeof(data) - 20);
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_OK);
}

static void
test_wrong_hash_fallback(void)
{
    u_char data[34];
    ngx_anytls_auth_step_t r;

    memset(data, 'X', sizeof(data));
    r = ngx_anytls_auth_process(ac, data, sizeof(data));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_FALLBACK);
    ASSERT_EQ(r.fallback_replay_len, sizeof(data));
    ASSERT_MEM(r.fallback_replay, data, sizeof(data));
}

static void
test_max_padding_waits_for_data(void)
{
    u_char data[34];
    ngx_anytls_auth_step_t r;

    /* 0xFFFF is the uint16_t max: need = 34 + 65535 = AUTH_BUF_SIZE,
     * so it does not trip the ERROR guard; auth waits for the padding. */
    memcpy(data, fuzz_password_hash, 32);
    data[32] = 0xff;
    data[33] = 0xff;

    r = ngx_anytls_auth_process(ac, data, sizeof(data));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);
}

static void
run_all_tests(void)
{
    set_up();   test_ok_no_padding();
    set_up();   test_ok_with_padding();
    set_up();   test_partial_input_more();
    set_up();   test_split_accumulation();
    set_up();   test_wrong_hash_fallback();
    set_up();   test_max_padding_waits_for_data();

    ngx_destroy_pool(pool);
}

TEST_MAIN()
