#!/usr/bin/perl

use warnings;
use strict;

use Digest::SHA qw/ sha256 /;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;

BEGIN {
    unshift @INC, $ENV{TEST_NGINX_LIB} if defined $ENV{TEST_NGINX_LIB};
}

use AnyTLS::Test qw/ CMD_SETTINGS frame /;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(1)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%
daemon off;
events { }
stream {
    %%TEST_GLOBALS_STREAM%%
    server {
        listen 127.0.0.1:8080;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
    }
}
EOF

$t->run();
my $client = stream('127.0.0.1:' . port(8080));
my $wire = sha256('test-password') . pack('n', 65535) . ('p' x 65535)
    . frame(CMD_SETTINGS, 0, "v=2\n");
$client->write($wire);

my $buffer = '';
my $authenticated = 0;
for (1 .. 32) {
    my $chunk = $client->read();
    last if !defined $chunk;
    $buffer .= $chunk;
    while (length($buffer) >= 7) {
        my ($cmd, undef, $len) = unpack('C N n', substr($buffer, 0, 7));
        last if length($buffer) < 7 + $len;
        substr($buffer, 0, 7 + $len, '');
        $authenticated = 1 if $cmd == 10;
    }
    last if $authenticated;
}

ok($authenticated,
    'maximum split authentication padding leaves following SETTINGS intact');
