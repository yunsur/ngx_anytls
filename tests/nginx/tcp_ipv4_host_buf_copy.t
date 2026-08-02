#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use Time::HiRes qw/ usleep /;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use AnyTLS::Test qw/
    CMD_SYN CMD_PUSH CMD_FIN CMD_SETTINGS
    auth_prefix frame socks5_ipv4_addr
    read_anytls_push tcp_echo_socket tcp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $tcp_server = tcp_echo_socket();
my $tcp_port = $tcp_server->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(1)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8080;

        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

$t->run_daemon(sub { tcp_echo_daemon($tcp_server) });
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));
my $payload = 'host_buf inline test payload';

# Full AnyTLS handshake
$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));

# Open TCP stream via IPv4 SOCKS5 address
# This exercises ngx_anytls_parse_socksaddr IPv4 path
# which now stores host string on addr->host_buf (inline, no pool)
$client->write(frame(CMD_SYN, 1, ''));
$client->write(frame(CMD_PUSH, 1,
    socks5_ipv4_addr('127.0.0.1', $tcp_port) . $payload));

is(read_anytls_push($client, 1), $payload,
    'TCP IPv4 stream: host_buf inline storage survives addr copy');

$client->write(frame(CMD_FIN, 1, ''));
