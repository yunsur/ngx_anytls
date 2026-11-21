#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use Time::HiRes qw/ usleep /;

BEGIN {
    unshift @INC, $ENV{TEST_NGINX_LIB} if defined $ENV{TEST_NGINX_LIB};
}

use AnyTLS::Test qw/
    CMD_SYN CMD_PUSH CMD_FIN CMD_SETTINGS
    auth_prefix frame socks5_ipv4_addr read_anytls_push
    tcp_echo_socket tcp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $upstream = tcp_echo_socket();
my $upstream_port = $upstream->sockport();
my $t = Test::Nginx->new()->has(qw/stream/)->plan(8)
    ->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%
daemon off;
events { }
stream {
    log_format capped '\$upstream_addr \$anytls_upstream_states_truncated '
                      '\$anytls_peak_active_streams \$anytls_peak_pending_input '
                      '\$anytls_peak_pending_output \$anytls_peak_frames';
    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/access.log capped;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
        anytls_max_upstream_states 2;
    }
    server {
        listen 127.0.0.1:8081;
        access_log %%TESTDIR%%/unlimited.log capped;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
        anytls_max_upstream_states 0;
    }
}
EOF

$t->run_daemon(sub { tcp_echo_daemon($upstream) });
$t->run();
my $client = stream('127.0.0.1:' . port(8080));
$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));

for my $id (1, 3, 5) {
    my $payload = "state-$id";
    $client->write(frame(CMD_SYN, $id));
    $client->write(frame(CMD_PUSH, $id,
        socks5_ipv4_addr('127.0.0.1', $upstream_port) . $payload));
    is(read_anytls_push($client, $id), $payload,
        "stream $id succeeds despite upstream history cap");
    $client->write(frame(CMD_FIN, $id));
}
$client->socket()->close();
usleep(100_000);

my $log = $t->read_file('access.log');
like($log, qr/\s1\s+\d+\s+\d+\s+\d+\s+\d+$/m,
    'state truncation and allocation-free high-water variables are logged');

my $unlimited = stream('127.0.0.1:' . port(8081));
$unlimited->write(auth_prefix('test-password'));
$unlimited->write(frame(CMD_SETTINGS, 0, "v=2\n"));

for my $id (11, 13, 15) {
    my $payload = "unlimited-$id";
    $unlimited->write(frame(CMD_SYN, $id));
    $unlimited->write(frame(CMD_PUSH, $id,
        socks5_ipv4_addr('127.0.0.1', $upstream_port) . $payload));
    is(read_anytls_push($unlimited, $id), $payload,
        "stream $id records unlimited upstream history");
    $unlimited->write(frame(CMD_FIN, $id));
}
$unlimited->socket()->close();
usleep(100_000);

my $unlimited_log = $t->read_file('unlimited.log');
like($unlimited_log, qr/\s0\s+\d+\s+\d+\s+\d+\s+\d+$/m,
    'zero upstream-state limit keeps unlimited-history semantics');
