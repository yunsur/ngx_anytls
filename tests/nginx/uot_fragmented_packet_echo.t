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
    auth_prefix frame uot_v2_packet_open uot_ipv4_packet
    read_anytls_push parse_uot_ipv4_packet
    udp_echo_socket udp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $udp_server = udp_echo_socket();
my $udp_port = $udp_server->sockport();

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

$t->run_daemon(sub { udp_echo_daemon($udp_server) });
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));
my $stream_id = 21;
my $payload = 'fragmented uot packet';
my $packet = uot_ipv4_packet('127.0.0.1', $udp_port, $payload);

$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->write(frame(CMD_SYN, $stream_id, ''));
$client->write(frame(CMD_PUSH, $stream_id, uot_v2_packet_open('127.0.0.1', $udp_port)));
$client->write(frame(CMD_PUSH, $stream_id, substr($packet, 0, 4)));
$client->write(frame(CMD_PUSH, $stream_id, substr($packet, 4)));

my (undef, undef, $body) = parse_uot_ipv4_packet(read_anytls_push($client, $stream_id));
is($body, $payload, 'UoT packet split across PUSH frames is reassembled');

$client->write(frame(CMD_FIN, $stream_id, ''));
