#!/usr/bin/perl

use warnings;
use strict;

use Time::HiRes qw/ time usleep /;
use IO::Socket::INET;
use Test::More;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

# Black-hole listener: backlog 1, never accepts.  A filler connection takes
# the accept-queue slot, so the fallback connect's SYN is dropped and the
# connect stays pending until anytls_fallback_connect_timeout expires.
my $blackhole = IO::Socket::INET->new(
    Proto     => 'tcp',
    LocalHost => '127.0.0.1',
    LocalPort => 0,
    Listen    => 1,
    Reuse     => 1,
)
    or die "failed to listen on blackhole port: $!";
my $blackhole_port = $blackhole->sockport();

my $filler1 = IO::Socket::INET->new(
    Proto    => 'tcp',
    PeerAddr => '127.0.0.1',
    PeerPort => $blackhole_port,
)
    or die "failed to open filler connection: $!";

my $filler2 = IO::Socket::INET->new(
    Proto    => 'tcp',
    PeerAddr => '127.0.0.1',
    PeerPort => $blackhole_port,
)
    or die "failed to open second filler connection: $!";

usleep(100_000);

my $t = Test::Nginx->new()->has(qw/stream/)->plan(3)
    ->write_file_expand('nginx.conf', <<"EOF");

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
        anytls_fallback 127.0.0.1:$blackhole_port;
        anytls_fallback_proxy_protocol off;
        anytls_fallback_connect_timeout 1s;
    }
}

EOF

$t->run();

my $client = stream('127.0.0.1:' . port(8080));

my $start = time();
$client->write('x' x 40);
my $eof = $client->read();
my $elapsed = time() - $start;

ok(!defined($eof) || $eof eq '',
    'fallback connect timeout closes client connection');
ok($elapsed >= 0.7,
    "client closed by timeout, not an early error (${elapsed}s elapsed)");

my $log = $t->read_file('error.log') // '';
like($log, qr/fallback upstream connect timed out/,
    'error log reports fallback connect timeout');

$filler1->close();
$filler2->close();
$blackhole->close();
