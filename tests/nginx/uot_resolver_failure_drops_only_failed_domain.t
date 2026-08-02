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
    auth_prefix frame uot_v2_packet_open uot_domain_packet
    read_anytls_push parse_uot_ipv4_packet
    udp_echo_socket udp_echo_daemon dns_socket dns_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $dns_server = dns_socket();
my $dns_port = $dns_server->sockport();
my $udp_server = udp_echo_socket();
my $udp_port = $udp_server->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(1)
    ->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%
    resolver 127.0.0.1:$dns_port valid=1s ipv6=off;
    resolver_timeout 1s;

    server {
        listen 127.0.0.1:8080;

        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

$t->run_daemon(sub {
    dns_daemon($dns_server, {
        'bad.test' => 'NXDOMAIN',
        'good.test' => '127.0.0.1',
    });
});
$t->run_daemon(sub { udp_echo_daemon($udp_server) });
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));
my $stream_id = 15;

$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->write(frame(CMD_SYN, $stream_id, ''));
$client->write(frame(CMD_PUSH, $stream_id, uot_v2_packet_open('127.0.0.1', $udp_port)));
$client->write(frame(CMD_PUSH, $stream_id,
    uot_domain_packet('bad.test', $udp_port, 'drop me')));
$client->write(frame(CMD_PUSH, $stream_id,
    uot_domain_packet('good.test', $udp_port, 'keep me')));

my (undef, undef, $body) = parse_uot_ipv4_packet(read_anytls_push($client, $stream_id));
is($body, 'keep me', 'resolver failure drops only failed UoT domain packets');

$client->write(frame(CMD_FIN, $stream_id, ''));
