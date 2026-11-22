#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use IO::Select;
use IO::Socket::INET;
use Test::More;

BEGIN {
    unshift @INC, $ENV{TEST_NGINX_LIB} if defined $ENV{TEST_NGINX_LIB};
}

use AnyTLS::Test qw/
    CMD_SYN CMD_PUSH CMD_FIN CMD_SETTINGS
    auth_prefix frame socks5_ipv4_addr
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

sub tcp_echo_concurrent_daemon {
    my ($server) = @_;
    my $readable = IO::Select->new($server);

    while (1) {
        for my $socket ($readable->can_read()) {
            if (fileno($socket) == fileno($server)) {
                my $client = $server->accept();
                $readable->add($client) if defined $client;
                next;
            }

            my $data = '';
            my $n = sysread($socket, $data, 65536);
            if (!defined $n || $n == 0) {
                $readable->remove($socket);
                close $socket;
                next;
            }

            my $offset = 0;
            while ($offset < $n) {
                my $written = syswrite($socket, $data, $n - $offset, $offset);
                die "echo write failed: $!"
                    if !defined $written || $written == 0;
                $offset += $written;
            }
        }
    }
}

my $upstream = IO::Socket::INET->new(
    Proto => 'tcp', LocalHost => '127.0.0.1', LocalPort => 0,
    Listen => 256, Reuse => 1) or die "listen failed: $!";
my $upstream_port = $upstream->sockport();
my $t = Test::Nginx->new()->has(qw/stream/)->plan(2)
    ->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%
daemon off;
events { worker_connections 1024; }
stream {
    %%TEST_GLOBALS_STREAM%%
    server {
        listen 127.0.0.1:8080;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
        anytls_max_streams 256;
    }
}
EOF

$t->run_daemon(sub { tcp_echo_concurrent_daemon($upstream) });
$t->run();

my $client = stream('127.0.0.1:' . port(8080));
my $wire_buffer = '';
my $address = socks5_ipv4_addr('127.0.0.1', $upstream_port);
$client->write(auth_prefix('test-password')
    . frame(CMD_SETTINGS, 0, "v=2\n"));

sub read_frame {
    while (length($wire_buffer) < 7) {
        my $chunk = $client->read();
        die 'unexpected EOF while reading frame header'
            if !defined $chunk;
        $wire_buffer .= $chunk;
    }

    my ($cmd, $sid, $length) = unpack('C N n', substr($wire_buffer, 0, 7));
    while (length($wire_buffer) < 7 + $length) {
        my $chunk = $client->read();
        die 'unexpected EOF while reading frame payload'
            if !defined $chunk;
        $wire_buffer .= $chunk;
    }

    my $data = substr($wire_buffer, 7, $length);
    substr($wire_buffer, 0, 7 + $length, '');
    return ($cmd, $sid, $data);
}

sub run_tiny_batch {
    my ($first_id, $count) = @_;
    my (%wanted, %echoed, %finished);
    my $wire = '';

    for my $ordinal (0 .. $count - 1) {
        my $sid = $first_id + $ordinal * 2;
        my $payload = chr(33 + $ordinal % 90);
        $wanted{$sid} = $payload;
        $wire .= frame(CMD_SYN, $sid)
            . frame(CMD_PUSH, $sid, $address . $payload);
    }
    $client->write($wire);

    while (keys(%echoed) < $count) {
        my ($cmd, $sid, $data) = read_frame();
        next if $cmd != CMD_PUSH || !exists $wanted{$sid};
        die "tiny payload mismatch for stream $sid"
            if $data ne $wanted{$sid};
        $echoed{$sid} = 1;
    }

    $wire = join('', map { frame(CMD_FIN, $_) } keys(%wanted));
    $client->write($wire);
    while (keys(%finished) < $count) {
        my ($cmd, $sid) = read_frame();
        next if $cmd != CMD_FIN || !exists $wanted{$sid};
        $finished{$sid} = 1;
    }

    return scalar keys(%echoed);
}

my $batch_size = 96;
is(run_tiny_batch(1, $batch_size), $batch_size,
    'tiny pending buffers drain after exceeding the cache object limit');
is(run_tiny_batch(1001, $batch_size), $batch_size,
    'session reuses the bounded cache for a second tiny-buffer batch');
undef $client;
