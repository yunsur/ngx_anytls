#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use IO::Socket::INET;
use Test::More;

BEGIN {
    unshift @INC, $ENV{TEST_NGINX_LIB} if defined $ENV{TEST_NGINX_LIB};
}

use AnyTLS::Test qw/ tcp_echo_socket tcp_echo_daemon /;
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $upstream = tcp_echo_socket();
my $upstream_port = $upstream->sockport();
my $t = Test::Nginx->new()->has(qw/stream/)->plan(1)
    ->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%
daemon off;
events { }
stream {
    %%TEST_GLOBALS_STREAM%%
    server {
        listen 127.0.0.1:8080;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:$upstream_port;
        anytls_fallback_proxy_protocol off;
    }
}
EOF

$t->run_daemon(sub { tcp_echo_daemon($upstream) });
$t->run();

my $client = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . port(8080), Proto => 'tcp', Timeout => 5)
    or die "connect failed: $!";
$client->autoflush(1);
my $payload = join('', map { chr(($_ * 37) & 0xff) } 0 .. 60000);
my $offset = 0;
while ($offset < length($payload)) {
    my $n = syswrite($client, $payload, length($payload) - $offset, $offset);
    die "write failed: $!" if !defined $n || $n == 0;
    $offset += $n;
}

my $echo = '';
while (length($echo) < length($payload)) {
    my $n = sysread($client, my $chunk, length($payload) - length($echo));
    last if !defined $n || $n == 0;
    $echo .= $chunk;
}

is($echo, $payload,
    'fallback replays the 34-byte prefix and same-read tail byte-for-byte');
