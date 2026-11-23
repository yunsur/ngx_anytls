#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use IO::Select;
use IO::Socket::INET;
use Socket qw/ SOL_SOCKET SO_RCVBUF /;
use Test::More;
use Time::HiRes qw/ sleep time /;

BEGIN {
    unshift @INC, $ENV{TEST_NGINX_LIB} if defined $ENV{TEST_NGINX_LIB};
}

use AnyTLS::Test qw/
    CMD_SYN CMD_PUSH CMD_FIN CMD_SETTINGS auth_prefix frame socks5_ipv4_addr
/;
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $upstream = IO::Socket::INET->new(
    Proto => 'tcp', LocalHost => '127.0.0.1', LocalPort => 0,
    Listen => 16, Reuse => 1) or die "listen failed: $!";
my $upstream_port = $upstream->sockport();
my $payload = join('', map { chr($_) } 0 .. 255) x 1024;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(3)
    ->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%
daemon off;
events { }
stream {
    %%TEST_GLOBALS_STREAM%%
    server {
        listen 127.0.0.1:8080 sndbuf=4k;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
        anytls_buffer_size 16377;
        anytls_max_pending_output 32768;
    }
}
EOF

$t->run_daemon(sub {
    my $peer = $upstream->accept() or die "accept failed: $!";
    my $marker = '';
    while (length($marker) < 3) {
        my $n = sysread($peer, $marker, 3 - length($marker), length($marker));
        die "upstream marker read failed: $!" if !defined $n || $n == 0;
    }

    sleep 0.05;
    my $offset = 0;
    while ($offset < length($payload)) {
        my $n = syswrite($peer, $payload, length($payload) - $offset, $offset);
        die "upstream payload write failed: $!" if !defined $n || $n == 0;
        $offset += $n;
    }
    shutdown($peer, 1) or die "upstream shutdown failed: $!";
    sleep 1;
});
$t->run();

my $client = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . port(8080),
    Proto => 'tcp',
    Timeout => 5,
) or die "client connect failed: $!";
setsockopt($client, SOL_SOCKET, SO_RCVBUF, pack('i', 4096))
    or die "set receive buffer failed: $!";

my $select = IO::Select->new($client);
my $wire = '';
my $received = '';
my $finished = 0;
my $synack = 0;
my $request = auth_prefix('test-password')
    . frame(CMD_SETTINGS, 0, "v=2\n")
    . frame(CMD_SYN, 1)
    . frame(CMD_PUSH, 1,
        socks5_ipv4_addr('127.0.0.1', $upstream_port) . 'go!');
syswrite($client, $request) == length($request)
    or die "client request write failed: $!";

my $deadline = time() + 5;
while (time() < $deadline && !$synack) {
    my @ready = $select->can_read($deadline - time());
    last if !@ready;

    my $n = sysread($client, my $chunk, 65536);
    last if !defined $n || $n == 0;
    $wire .= $chunk;

    while (length($wire) >= 7) {
        my ($cmd, $stream_id, $length) = unpack('C N n', substr($wire, 0, 7));
        last if length($wire) < 7 + $length;
        my $data = substr($wire, 7, $length);
        substr($wire, 0, 7 + $length, '');

        $received .= $data if $cmd == CMD_PUSH && $stream_id == 1;
        $synack = 1 if $cmd == 7 && $stream_id == 1;
    }
}
die 'upstream did not acknowledge the stream' if !$synack;

my $fin = frame(CMD_FIN, 1);
syswrite($client, $fin) == length($fin)
    or die "client FIN write failed: $!";
sleep 0.3;

$deadline = time() + 10;
while (time() < $deadline && !$finished) {
    my @ready = $select->can_read($deadline - time());
    last if !@ready;

    my $n = sysread($client, my $chunk, 65536);
    last if !defined $n || $n == 0;
    $wire .= $chunk;

    while (length($wire) >= 7) {
        my ($cmd, $stream_id, $length) = unpack('C N n', substr($wire, 0, 7));
        last if length($wire) < 7 + $length;
        my $data = substr($wire, 7, $length);
        substr($wire, 0, 7 + $length, '');

        $received .= $data if $cmd == CMD_PUSH && $stream_id == 1;
        $finished = 1 if $cmd == CMD_FIN && $stream_id == 1;
    }
}

is(length($received), length($payload),
    'ready upstream data resumes after client output pressure drains');
ok($received eq $payload,
    'resumed upstream payload remains byte-for-byte intact');
ok($finished,
    'upstream EOF reaches the half-closed client stream after pressure drains');
