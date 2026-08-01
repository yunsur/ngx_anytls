#include "test_helpers.h"
#include "ngx_anytls_protocol.h"

static void
test_push_roundtrip(void)
{
    u_char buf[64];
    u_char data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    ngx_anytls_frame_t frame;
    size_t consumed = 0;

    ASSERT_NOTNULL(ngx_anytls_write_frame_header(buf, NGX_ANYTLS_CMD_PSH,
                                                 42, sizeof(data)));
    memcpy(buf + NGX_ANYTLS_FRAME_HEADER_LEN, data, sizeof(data));

    ASSERT_EQ(ngx_anytls_parse_frame(buf, buf + 7 + sizeof(data),
                                     &frame, &consumed), NGX_OK);
    ASSERT_EQ((int) frame.cmd, (int) NGX_ANYTLS_CMD_PSH);
    ASSERT_EQ(frame.stream_id, 42u);
    ASSERT_EQ(frame.data_len, sizeof(data));
    ASSERT_NOTNULL(frame.data);
    ASSERT_MEM(frame.data, data, sizeof(data));
    ASSERT_EQ(consumed, sizeof(data) + NGX_ANYTLS_FRAME_HEADER_LEN);
}

static void
test_fin_zero_data(void)
{
    u_char buf[16];
    ngx_anytls_frame_t frame;
    size_t consumed = 0;

    ASSERT_NOTNULL(ngx_anytls_write_frame_header(buf, NGX_ANYTLS_CMD_FIN,
                                                 0xFFFFFFFFu, 0));
    ASSERT_EQ(ngx_anytls_parse_frame(buf, buf + NGX_ANYTLS_FRAME_HEADER_LEN,
                                     &frame, &consumed), NGX_OK);
    ASSERT_EQ((int) frame.cmd, (int) NGX_ANYTLS_CMD_FIN);
    ASSERT_EQ(frame.stream_id, 0xFFFFFFFFu);
    ASSERT_EQ(frame.data_len, 0u);
    ASSERT_NULL(frame.data);
}

static void
test_truncated_header(void)
{
    u_char buf[5] = { 0x01, 0x00, 0x00, 0x00, 0x01 };
    ngx_anytls_frame_t frame;
    size_t consumed = 0;

    ASSERT_EQ(ngx_anytls_parse_frame(buf, buf + sizeof(buf),
                                     &frame, &consumed), NGX_AGAIN);
}

static void
test_truncated_payload(void)
{
    u_char buf[10];
    ngx_anytls_frame_t frame;
    size_t consumed = 0;

    ASSERT_NOTNULL(ngx_anytls_write_frame_header(buf, NGX_ANYTLS_CMD_PSH,
                                                 1, 8));
    memcpy(buf + NGX_ANYTLS_FRAME_HEADER_LEN, "abc", 3);

    ASSERT_EQ(ngx_anytls_parse_frame(buf, buf + NGX_ANYTLS_FRAME_HEADER_LEN + 3,
                                     &frame, &consumed), NGX_AGAIN);
}

static void
test_unknown_cmd_tolerated(void)
{
    u_char buf[16];
    ngx_anytls_frame_t frame;
    size_t consumed = 0;

    ASSERT_NOTNULL(ngx_anytls_write_frame_header(buf, 99, 7, 5));
    memcpy(buf + NGX_ANYTLS_FRAME_HEADER_LEN, "hello", 5);

    ASSERT_EQ(ngx_anytls_parse_frame(buf, buf + 12, &frame, &consumed), NGX_OK);
    ASSERT_EQ(consumed, 12u);
    ASSERT_NULL(frame.data);
}

static void
test_max_payload_length(void)
{
    u_char buf[NGX_ANYTLS_FRAME_HEADER_LEN + NGX_ANYTLS_MAX_FRAME_DATA];
    ngx_anytls_frame_t frame;
    size_t consumed = 0;

    memset(buf, 0, sizeof(buf));
    ASSERT_NOTNULL(ngx_anytls_write_frame_header(buf, NGX_ANYTLS_CMD_PSH, 1,
                                                 NGX_ANYTLS_MAX_FRAME_DATA));

    ASSERT_EQ(ngx_anytls_parse_frame(buf, buf + sizeof(buf),
                                     &frame, &consumed), NGX_OK);
    ASSERT_EQ(frame.data_len, NGX_ANYTLS_MAX_FRAME_DATA);
    ASSERT_EQ(consumed, sizeof(buf));
}

static void
run_all_tests(void)
{
    test_push_roundtrip();
    test_fin_zero_data();
    test_truncated_header();
    test_truncated_payload();
    test_unknown_cmd_tolerated();
    test_max_payload_length();
}

TEST_MAIN()
