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
    auth_prefix frame socks5_domain_addr
    read_anytls_push dns_socket dns_daemon tcp_echo_socket tcp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $dns_server = dns_socket();
my $dns_port = $dns_server->sockport();
my $tcp_server = tcp_echo_socket();
my $tcp_port = $tcp_server->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(1)
    ->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%
    resolver 127.0.0.1:$dns_port valid=5s ipv6=off;
    resolver_timeout 1s;

    server {
        listen 127.0.0.1:8080;

        anytls on;
        anytls_password test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

$t->run_daemon(sub { dns_daemon($dns_server, { 'tcp.test' => '127.0.0.1' }) });
$t->run_daemon(sub { tcp_echo_daemon($tcp_server) });
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));
my $stream_id = 17;
my $payload = 'tcp async domain echo';

$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->write(frame(CMD_SYN, $stream_id, ''));
$client->write(frame(CMD_PUSH, $stream_id,
    socks5_domain_addr('tcp.test', $tcp_port) . $payload));

is(read_anytls_push($client, $stream_id), $payload,
    'TCP domain target resolves through nginx async resolver');

$client->write(frame(CMD_FIN, $stream_id, ''));
