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
test_wrong_hash_preserves_unconsumed_tail(void)
{
    u_char data[34 + 1024];
    u_char replay[sizeof(data)];
    ngx_anytls_auth_step_t r;

    memset(data, 'X', 34);
    memset(data + 34, 'T', sizeof(data) - 34);

    r = ngx_anytls_auth_process(ac, data, sizeof(data));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_FALLBACK);
    ASSERT_EQ(r.consumed, 34u);
    ASSERT_EQ(r.fallback_replay_len, 34u);

    memcpy(replay, r.fallback_replay, r.fallback_replay_len);
    memcpy(replay + r.fallback_replay_len, data + r.consumed,
           sizeof(data) - r.consumed);
    ASSERT_MEM(replay, data, sizeof(data));
}


static void
test_auth_prefix_fragmented_at_every_byte(void)
{
    u_char data[34];
    ngx_anytls_auth_step_t r;
    size_t i;

    memcpy(data, fuzz_password_hash, 32);
    data[32] = 0;
    data[33] = 0;

    for (i = 0; i < sizeof(data); i++) {
        r = ngx_anytls_auth_process(ac, data + i, 1);
        ASSERT_EQ(r.consumed, 1u);
        ASSERT_EQ((int) r.result,
                  i + 1 == sizeof(data)
                  ? (int) NGX_ANYTLS_AUTH_OK
                  : (int) NGX_ANYTLS_AUTH_MORE);
    }
}


static void
test_max_padding_waits_for_data(void)
{
    u_char data[34];
    ngx_anytls_auth_step_t r;

    /* 0xFFFF is the uint16_t max; auth must wait for all padding without
     * retaining the padding bytes. */
    memcpy(data, fuzz_password_hash, 32);
    data[32] = 0xff;
    data[33] = 0xff;

    r = ngx_anytls_auth_process(ac, data, sizeof(data));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);
}

static void
test_max_padding_split_leaves_following_frame(void)
{
    u_char prefix[34];
    u_char chunk[4096 + NGX_ANYTLS_FRAME_HEADER_LEN];
    u_char frame[NGX_ANYTLS_FRAME_HEADER_LEN];
    ngx_anytls_auth_step_t r;
    size_t remaining, n;

    memcpy(prefix, fuzz_password_hash, 32);
    prefix[32] = 0xff;
    prefix[33] = 0xff;

    r = ngx_anytls_auth_process(ac, prefix, sizeof(prefix));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);
    ASSERT_EQ(r.consumed, sizeof(prefix));

    memset(chunk, 'p', sizeof(chunk));
    ASSERT_NOTNULL(ngx_anytls_write_frame_header(frame,
                                                 NGX_ANYTLS_CMD_SETTINGS,
                                                 0, 0));

    remaining = 65535;
    while (remaining > 4096) {
        r = ngx_anytls_auth_process(ac, chunk, 4096);
        ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);
        ASSERT_EQ(r.consumed, 4096u);
        remaining -= 4096;
    }

    n = remaining;
    memcpy(chunk + n, frame, sizeof(frame));
    r = ngx_anytls_auth_process(ac, chunk, n + sizeof(frame));
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_OK);
    ASSERT_EQ(r.consumed, n);
    ASSERT_MEM(chunk + r.consumed, frame, sizeof(frame));
}


static void
test_padding_split_keeps_match(void)
{
    u_char data[34 + 100];
    ngx_anytls_auth_step_t r;

    /* valid hash + large padding delivered in slow chunks: after the
     * hash matches, the user scan is cached, and the padding wait must
     * still accumulate and authenticate */
    memcpy(data, fuzz_password_hash, 32);
    data[32] = 0;
    data[33] = 100;
    memset(data + 34, 'p', 100);

    r = ngx_anytls_auth_process(ac, data, 34);
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);

    r = ngx_anytls_auth_process(ac, data + 34, 60);
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_MORE);

    r = ngx_anytls_auth_process(ac, data + 94, 40);
    ASSERT_EQ((int) r.result, (int) NGX_ANYTLS_AUTH_OK);
    ASSERT_EQ((int) ac->user_name.len, 8);
    ASSERT_MEM(ac->user_name.data, "test-user", 8);
}

static void
run_all_tests(void)
{
    set_up();   test_ok_no_padding();
    set_up();   test_ok_with_padding();
    set_up();   test_partial_input_more();
    set_up();   test_split_accumulation();
    set_up();   test_wrong_hash_fallback();
    set_up();   test_wrong_hash_preserves_unconsumed_tail();
    set_up();   test_auth_prefix_fragmented_at_every_byte();
    set_up();   test_max_padding_waits_for_data();
    set_up();   test_max_padding_split_leaves_following_frame();
    set_up();   test_padding_split_keeps_match();

    ngx_destroy_pool(pool);
}

TEST_MAIN()
