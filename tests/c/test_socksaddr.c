#include "test_helpers.h"
#include "ngx_anytls_socksaddr.h"

static ngx_pool_t *pool;

static void
test_ipv4_parse(void)
{
    u_char data[] = { 0x01, 127, 0, 0, 1, 0x00, 0x35 };  /* atyp=1 127.0.0.1:53 */
    ngx_anytls_addr_t addr;

    ASSERT_EQ(ngx_anytls_parse_socksaddr(pool, data, sizeof(data), &addr),
              NGX_OK);
    ASSERT_EQ(addr.atyp, 1u);
    ASSERT_EQ(addr.port, 53u);
    ASSERT_EQ(addr.host.len, sizeof("127.0.0.1") - 1);
    ASSERT_MEM(addr.host.data, "127.0.0.1", sizeof("127.0.0.1") - 1);
    ASSERT_EQ(addr.socklen, (socklen_t) sizeof(struct sockaddr_in));
    ASSERT_EQ(addr.has_sockaddr, 1u);
    ASSERT_EQ(addr.consumed, sizeof(data));
}

static void
test_ipv6_parse(void)
{
    u_char data[19];
    ngx_anytls_addr_t addr;

    data[0] = 0x04;  /* atyp=4 */
    memset(&data[1], 0x10, 16);
    data[17] = 0x01;
    data[18] = 0xBB;  /* port 443 */

    ASSERT_EQ(ngx_anytls_parse_socksaddr(pool, data, sizeof(data), &addr),
              NGX_OK);
    ASSERT_EQ(addr.port, 443u);
    ASSERT_EQ(addr.socklen, (socklen_t) sizeof(struct sockaddr_in6));
    ASSERT_EQ(addr.has_sockaddr, 1u);
    ASSERT_EQ(addr.consumed, sizeof(data));
}

static void
test_domain_parse(void)
{
    u_char data[] = { 0x03, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                      0x00, 0x50 };  /* atyp=3 "example":80 */
    ngx_anytls_addr_t addr;

    ASSERT_EQ(ngx_anytls_parse_socksaddr(pool, data, sizeof(data), &addr),
              NGX_OK);
    ASSERT_EQ(addr.atyp, 3u);
    ASSERT_EQ(addr.port, 80u);
    ASSERT_EQ(addr.host.len, 7u);
    ASSERT_MEM(addr.host.data, "example", 7);
    ASSERT_EQ(addr.consumed, sizeof(data));
}

static void
test_truncated_returns_again(void)
{
    u_char data[] = { 0x01, 127, 0 };  /* IPv4 with missing port */
    ngx_anytls_addr_t addr;

    ASSERT_EQ(ngx_anytls_parse_socksaddr(pool, data, sizeof(data), &addr),
              NGX_AGAIN);
}

static void
test_bad_atyp_rejected(void)
{
    u_char data[] = { 0x09, 0x00, 0x00 };
    ngx_anytls_addr_t addr;

    ASSERT_EQ(ngx_anytls_parse_socksaddr(pool, data, sizeof(data), &addr),
              NGX_ERROR);
}

static void
test_uot_ipv4_packet(void)
{
    u_char data[] = { 0x00, 127, 0, 0, 1, 0x00, 0x35, 0x00, 0x05,
                      'h', 'e', 'l', 'l', 'o' };
    ngx_anytls_addr_t addr;
    u_char *payload;
    size_t payload_len, consumed;

    ASSERT_EQ(ngx_anytls_parse_uot_packet(pool, data, sizeof(data), &addr,
                                          &payload, &payload_len, &consumed),
              NGX_OK);
    ASSERT_EQ(payload_len, 5u);
    ASSERT_MEM(payload, "hello", 5);
    ASSERT_EQ(consumed, sizeof(data));
    ASSERT_EQ(addr.port, 53u);
}

static void
test_uot_domain_packet(void)
{
    u_char data[] = { 0x02, 3, 'a', 'b', 'c', 0x00, 0x50, 0x00, 0x02,
                      'x', 'y' };
    ngx_anytls_addr_t addr;
    u_char *payload;
    size_t payload_len, consumed;

    ASSERT_EQ(ngx_anytls_parse_uot_packet(pool, data, sizeof(data), &addr,
                                          &payload, &payload_len, &consumed),
              NGX_OK);
    ASSERT_EQ(payload_len, 2u);
    ASSERT_MEM(payload, "xy", 2);
    ASSERT_EQ(consumed, sizeof(data));
}

static void
test_uot_truncated_payload(void)
{
    u_char data[] = { 0x00, 127, 0, 0, 1, 0x00, 0x35, 0x00, 0x05, 'h' };
    ngx_anytls_addr_t addr;
    u_char *payload;
    size_t payload_len, consumed;

    ASSERT_EQ(ngx_anytls_parse_uot_packet(pool, data, sizeof(data), &addr,
                                          &payload, &payload_len, &consumed),
              NGX_AGAIN);
}

static void
run_all_tests(void)
{
    pool = ngx_create_pool(4096, NULL);
    ASSERT_NOTNULL(pool);

    test_ipv4_parse();
    test_ipv6_parse();
    test_domain_parse();
    test_truncated_returns_again();
    test_bad_atyp_rejected();
    test_uot_ipv4_packet();
    test_uot_domain_packet();
    test_uot_truncated_payload();

    ngx_destroy_pool(pool);
}

TEST_MAIN()
