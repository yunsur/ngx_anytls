#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use IO::Select;

BEGIN {
    unshift @INC, $ENV{TEST_NGINX_LIB} if defined $ENV{TEST_NGINX_LIB};
}

use AnyTLS::Test qw/
    CMD_SYN CMD_PUSH CMD_FIN CMD_SETTINGS
    auth_prefix frame socks5_ipv4_addr
    tcp_echo_socket

/;

local $ENV{TEST_NGINX_TIMEOUT} = 300;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;
my $seed = defined $ENV{ANYTLS_FUZZ_SEED}
    ? int($ENV{ANYTLS_FUZZ_SEED}) : 0x41544c53;
srand($seed);
my $stream_count = defined $ENV{ANYTLS_FUZZ_STREAMS}
    ? int($ENV{ANYTLS_FUZZ_STREAMS}) : 4096;

sub write_fragmented {
    my ($client, $data) = @_;

    while (length($data) != 0) {
        my $len = 1 + int(rand(73));
        $len = length($data) if $len > length($data);
        $client->write(substr($data, 0, $len, ''));
    }
}

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
                if (!defined $written || $written == 0) {
                    $readable->remove($socket);
                    close $socket;
                    last;
                }
                $offset += $written;
            }
        }
    }
}


my $upstream = tcp_echo_socket();
my $upstream_port = $upstream->sockport();
my $t = Test::Nginx->new()->has(qw/stream/)->plan(2)
    ->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%
daemon off;
events { worker_connections 8192; }
stream {
    %%TEST_GLOBALS_STREAM%%
    server {
        listen 127.0.0.1:8080;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
        anytls_max_streams 64;
    }
}
EOF

$t->run_daemon(sub { tcp_echo_concurrent_daemon($upstream) });
$t->run();
my $client = stream('127.0.0.1:' . port(8080));
$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));

my $buffer = '';
my $read_frame = sub {
    my ($id, $ordinal) = @_;

    while (length($buffer) < 7) {
        my $chunk = $client->read();
        die "unexpected EOF at stream $id ordinal $ordinal"
            if !defined $chunk;
        $buffer .= $chunk;
    }
    my ($cmd, $sid, $len) = unpack('C N n', substr($buffer, 0, 7));
    while (length($buffer) < 7 + $len) {
        my $chunk = $client->read();
        die "unexpected payload EOF at stream $id ordinal $ordinal"
            if !defined $chunk;
        $buffer .= $chunk;
    }
    my $data = substr($buffer, 7, $len);
    substr($buffer, 0, 7 + $len, '');
    return ($cmd, $sid, $data);
};

my $complete = 0;
my $batch_size = 4;
for (my $base = 0; $base < $stream_count; $base += $batch_size) {
    my $end = $base + $batch_size;
    $end = $stream_count if $end > $stream_count;
    my (%wanted, %echoed, %done);
    my $wire = '';

    for my $ordinal ($base .. $end - 1) {
        my $id = $ordinal * 2 + 1;
        my $payload_len = 4 + int(rand(125));
        my $payload = pack('N', $ordinal) . ('x' x ($payload_len - 4));
        $wanted{$id} = $payload;
        $echoed{$id} = '';
        $wire .= frame(CMD_SYN, $id)
            . frame(CMD_PUSH, $id,
                socks5_ipv4_addr('127.0.0.1', $upstream_port) . $payload);
    }
    write_fragmented($client, $wire);

    while (keys(%done) < $end - $base) {
        my ($cmd, $sid, $data) = $read_frame->($base * 2 + 1, $base);
        next if $cmd != CMD_PUSH || !exists $wanted{$sid} || $done{$sid};
        $echoed{$sid} .= $data;
        next if length($echoed{$sid}) < length($wanted{$sid});
        die "echo mismatch at stream $sid"
            if $echoed{$sid} ne $wanted{$sid};
        $done{$sid} = 1;
    }

    $wire = '';
    my %finished;
    for my $sid (keys %wanted) {
        $wire .= frame(CMD_FIN, $sid);
        $finished{$sid} = 0;
    }
    write_fragmented($client, $wire);

    my $finished = 0;
    while ($finished < $end - $base) {
        my ($cmd, $sid) = $read_frame->($base * 2 + 1, $base);
        next if $cmd != CMD_FIN || !exists $finished{$sid}
            || $finished{$sid};
        $finished{$sid} = 1;
        $finished++;
    }
    $complete += $end - $base;
}

is($complete, $stream_count,
    "single session completes $stream_count churned streams");

my $last = $stream_count * 2 + 1;
write_fragmented($client, frame(CMD_SYN, $last)
    . frame(CMD_PUSH, $last,
        socks5_ipv4_addr('127.0.0.1', $upstream_port) . 'after-churn'));
my $found = 0;
while (!$found) {
    while (length($buffer) < 7) {
        my $chunk = $client->read();
        die 'unexpected EOF after churn' if !defined $chunk;
        $buffer .= $chunk;
    }
    my ($cmd, $sid, $len) = unpack('C N n', substr($buffer, 0, 7));
    while (length($buffer) < 7 + $len) {
        $buffer .= $client->read();
    }
    my $data = substr($buffer, 7, $len);
    substr($buffer, 0, 7 + $len, '');
    $found = 1 if $cmd == CMD_PUSH && $sid == $last && $data eq 'after-churn';
}
ok($found, 'stream lookup and creation still work after churn');
