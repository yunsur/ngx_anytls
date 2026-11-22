#include "ngx_anytls_client_buffer.h"
#include "test_helpers.h"

static void
test_initial_capacity_and_auth_bytes(void)
{
    ngx_anytls_client_buffer_t buffer;

    ngx_memzero(&buffer, sizeof(buffer));
    ASSERT_EQ(ngx_anytls_client_buffer_init(&buffer, NULL), NGX_OK);
    ASSERT_NOTNULL(buffer.data);
    ASSERT_EQ(buffer.capacity, NGX_ANYTLS_CLIENT_BUFFER_INITIAL_SIZE);

    ngx_memset(buffer.data, 0xff, 7);
    buffer.remnant_len = 7;
    ASSERT_EQ(ngx_anytls_client_buffer_prepare(&buffer, 0, NULL), NGX_OK);
    ASSERT_EQ(buffer.capacity, NGX_ANYTLS_CLIENT_BUFFER_INITIAL_SIZE);

    ngx_anytls_client_buffer_destroy(&buffer);
    ASSERT_NULL(buffer.data);
    ASSERT_EQ(buffer.capacity, 0);
    ASSERT_EQ(buffer.remnant_len, 0);
}


static void
test_fragmented_header_grows_and_preserves_bytes(void)
{
    ngx_anytls_client_buffer_t buffer;
    u_char header[NGX_ANYTLS_FRAME_HEADER_LEN] = {
        NGX_ANYTLS_CMD_PSH, 0, 0, 0, 1, 0x13, 0x88
    };

    ngx_memzero(&buffer, sizeof(buffer));
    ASSERT_EQ(ngx_anytls_client_buffer_init(&buffer, NULL), NGX_OK);

    ngx_memcpy(buffer.data, header, sizeof(header) - 1);
    buffer.remnant_len = sizeof(header) - 1;
    ASSERT_EQ(ngx_anytls_client_buffer_prepare(&buffer, 1, NULL), NGX_OK);
    ASSERT_EQ(buffer.capacity, NGX_ANYTLS_CLIENT_BUFFER_INITIAL_SIZE);

    buffer.data[sizeof(header) - 1] = header[sizeof(header) - 1];
    buffer.remnant_len = sizeof(header);
    ASSERT_EQ(ngx_anytls_client_buffer_prepare(&buffer, 1, NULL), NGX_OK);
    ASSERT_EQ(buffer.capacity, NGX_ANYTLS_FRAME_HEADER_LEN + 5000);
    ASSERT_MEM(buffer.data, header, sizeof(header));

    ngx_anytls_client_buffer_destroy(&buffer);
}


static void
test_maximum_frame_releases_and_regrows(void)
{
    ngx_anytls_client_buffer_t buffer;
    u_char header[NGX_ANYTLS_FRAME_HEADER_LEN] = {
        NGX_ANYTLS_CMD_PSH, 0, 0, 0, 3, 0xff, 0xff
    };

    ngx_memzero(&buffer, sizeof(buffer));
    ASSERT_EQ(ngx_anytls_client_buffer_init(&buffer, NULL), NGX_OK);
    ngx_memcpy(buffer.data, header, sizeof(header));
    buffer.remnant_len = sizeof(header);

    ASSERT_EQ(ngx_anytls_client_buffer_prepare(&buffer, 1, NULL), NGX_OK);
    ASSERT_EQ(buffer.capacity,
              NGX_ANYTLS_FRAME_HEADER_LEN + NGX_ANYTLS_MAX_FRAME_DATA);
    ASSERT_MEM(buffer.data, header, sizeof(header));

    buffer.remnant_len = 1;
    ngx_anytls_client_buffer_release_oversized(&buffer);
    ASSERT_NOTNULL(buffer.data);

    buffer.remnant_len = 0;
    ngx_anytls_client_buffer_release_oversized(&buffer);
    ASSERT_NULL(buffer.data);
    ASSERT_EQ(buffer.capacity, 0);

    ASSERT_EQ(ngx_anytls_client_buffer_prepare(&buffer, 1, NULL), NGX_OK);
    ASSERT_NOTNULL(buffer.data);
    ASSERT_EQ(buffer.capacity, NGX_ANYTLS_CLIENT_BUFFER_INITIAL_SIZE);

    ngx_anytls_client_buffer_destroy(&buffer);
}


static void
test_invalid_remnant_is_rejected(void)
{
    ngx_anytls_client_buffer_t buffer;

    ngx_memzero(&buffer, sizeof(buffer));
    ASSERT_EQ(ngx_anytls_client_buffer_init(&buffer, NULL), NGX_OK);
    buffer.remnant_len = buffer.capacity + 1;
    ASSERT_EQ(ngx_anytls_client_buffer_prepare(&buffer, 1, NULL), NGX_ERROR);
    ngx_anytls_client_buffer_destroy(&buffer);
}


static void
run_all_tests(void)
{
    test_initial_capacity_and_auth_bytes();
    test_fragmented_header_grows_and_preserves_bytes();
    test_maximum_frame_releases_and_regrows();
    test_invalid_remnant_is_rejected();
}

TEST_MAIN()
