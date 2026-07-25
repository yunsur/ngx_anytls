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
    auth_prefix frame uot_v2_connect_open uot_v2_connect_datagram
    read_anytls_push udp_echo_socket udp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $udp_server = udp_echo_socket();
my $udp_port = $udp_server->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(2)
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
        anytls_password test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

$t->run_daemon(sub { udp_echo_daemon($udp_server) });
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));
my $stream_id = 19;
my $payload = 'uot v2 connect echo';

$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->write(frame(CMD_SYN, $stream_id, ''));
$client->write(frame(CMD_PUSH, $stream_id, uot_v2_connect_open('127.0.0.1', $udp_port)));
$client->write(frame(CMD_PUSH, $stream_id, uot_v2_connect_datagram($payload)));

my $response = read_anytls_push($client, $stream_id);
my ($len, $body) = unpack('n a*', $response);

is($len, length($payload), 'UoT V2 connect response has length prefix');
is($body, $payload, 'UoT V2 connect receives UDP echo response');

$client->write(frame(CMD_FIN, $stream_id, ''));
