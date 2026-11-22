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
    auth_prefix frame socks5_ipv4_addr
    tcp_echo_socket tcp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $upstream = tcp_echo_socket();
my $upstream_port = $upstream->sockport();
my $t = Test::Nginx->new()->has(qw/stream/)->plan(3)
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

$t->run_daemon(sub { tcp_echo_daemon($upstream) });
$t->run();

my $client = stream('127.0.0.1:' . port(8080));
my $wire_buffer = '';
my $stream_id = 41;
$client->write(auth_prefix('test-password')
    . frame(CMD_SETTINGS, 0, "v=2\n")
    . frame(CMD_SYN, $stream_id));

my $address = socks5_ipv4_addr('127.0.0.1', $upstream_port);
my $maximum = patterned(65535 - length($address));
my $repeat = 8;
my $following = 'same-write-after-maximum-frames';
my $wire = frame(CMD_PUSH, $stream_id, $address . $maximum)
    . join('', map { frame(CMD_PUSH, $stream_id, $maximum) } 2 .. $repeat)
    . frame(CMD_PUSH, $stream_id, $following);
my $expected = $maximum x $repeat . $following;

$client->write(substr($wire, 0, 6, ''));
usleep(20_000);
write_fragmented($client, $wire, 3001);

is(read_stream_bytes($client, $stream_id, length($expected)),
   $expected,
   'fragmented maximum frames preserve the following frame');

$client->write(frame(CMD_FIN, $stream_id));
ok(wait_stream_fin($client, $stream_id),
   'maximum-frame stream closes before session reactivation');

my $next_stream_id = 43;
my $reactivated = patterned(8192);
my $after_reactivation = 'same-write-after-session-reactivation';
$client->write(frame(CMD_SYN, $next_stream_id)
    . frame(CMD_PUSH, $next_stream_id, $address . $reactivated)
    . frame(CMD_PUSH, $next_stream_id, $after_reactivation));

is(read_stream_bytes($client, $next_stream_id,
                     length($reactivated) + length($after_reactivation)),
   $reactivated . $after_reactivation,
   'idle session reactivates without losing trailing data');

$client->write(frame(CMD_FIN, $next_stream_id));

sub patterned {
    my ($size) = @_;
    my $pattern = join('', map { chr(33 + ($_ % 90)) } 0 .. 255);
    my $data = $pattern x int(($size + length($pattern) - 1)
        / length($pattern));
    return substr($data, 0, $size);
}

sub write_fragmented {
    my ($socket, $data, $size) = @_;
    while (length($data) != 0) {
        my $length = length($data) < $size ? length($data) : $size;
        $socket->write(substr($data, 0, $length, ''));
    }
}

sub read_stream_bytes {
    my ($socket, $wanted_stream, $wanted_length) = @_;
    my $payload = '';

    while (length($payload) < $wanted_length) {
        my ($cmd, $sid, $data) = read_frame($socket);
        $payload .= $data if $cmd == CMD_PUSH && $sid == $wanted_stream;
    }

    return $payload;
}

sub wait_stream_fin {
    my ($socket, $wanted_stream) = @_;

    while (1) {
        my ($cmd, $sid) = read_frame($socket);
        return 1 if $cmd == CMD_FIN && $sid == $wanted_stream;
    }
}

sub read_frame {
    my ($socket) = @_;

    while (length($wire_buffer) < 7) {
        my $chunk = $socket->read();
        die 'unexpected EOF while reading frame header'
            if !defined $chunk;
        $wire_buffer .= $chunk;
    }

    my ($cmd, $sid, $length) = unpack('C N n', substr($wire_buffer, 0, 7));
    while (length($wire_buffer) < 7 + $length) {
        my $chunk = $socket->read();
        die 'unexpected EOF while reading frame payload'
            if !defined $chunk;
        $wire_buffer .= $chunk;
    }

    my $data = substr($wire_buffer, 7, $length);
    substr($wire_buffer, 0, 7 + $length, '');
    return ($cmd, $sid, $data);
}
