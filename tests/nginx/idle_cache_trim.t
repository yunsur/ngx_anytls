#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use Time::HiRes qw/ sleep /;

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
my $t = Test::Nginx->new()->has(qw/stream/)->plan(4)
    ->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%
daemon off;
events { worker_connections 1024; }
stream {
    %%TEST_GLOBALS_STREAM%%
    log_format idle_cache '\$anytls_idle_cache_trims';
    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/access.log idle_cache;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
    }
}
EOF

$t->run_daemon(sub { tcp_echo_daemon($upstream) });
$t->run();

my $address = socks5_ipv4_addr('127.0.0.1', $upstream_port);

sub new_session {
    my $client = stream('127.0.0.1:' . port(8080));
    my $buffer = '';

    $client->write(auth_prefix('test-password')
        . frame(CMD_SETTINGS, 0, "v=2\n"));
    return ($client, \$buffer);
}

sub read_frame {
    my ($client, $buffer) = @_;

    while (length($$buffer) < 7) {
        my $chunk = $client->read();
        die 'unexpected EOF while reading frame header'
            if !defined $chunk;
        $$buffer .= $chunk;
    }

    my ($cmd, $sid, $length) = unpack('C N n', substr($$buffer, 0, 7));
    while (length($$buffer) < 7 + $length) {
        my $chunk = $client->read();
        die 'unexpected EOF while reading frame payload'
            if !defined $chunk;
        $$buffer .= $chunk;
    }

    my $data = substr($$buffer, 7, $length);
    substr($$buffer, 0, 7 + $length, '');
    return ($cmd, $sid, $data);
}

sub run_stream {
    my ($client, $buffer, $sid, $payload, $hold) = @_;

    $client->write(frame(CMD_SYN, $sid)
        . frame(CMD_PUSH, $sid, $address . $payload));
    while (1) {
        my ($cmd, $got_sid, $data) = read_frame($client, $buffer);
        next if $cmd != CMD_PUSH || $got_sid != $sid;
        die "payload mismatch for stream $sid" if $data ne $payload;
        last;
    }

    sleep($hold) if $hold;
    $client->write(frame(CMD_FIN, $sid));
    while (1) {
        my ($cmd, $got_sid) = read_frame($client, $buffer);
        last if $cmd == CMD_FIN && $got_sid == $sid;
    }

    return $payload;
}

my ($grace_client, $grace_buffer) = new_session();
run_stream($grace_client, $grace_buffer, 1, 'warm-grace', 0);
sleep 0.1;
is(run_stream($grace_client, $grace_buffer, 3, 'active-past-timer', 1.1),
    'active-past-timer', 'new stream cancels idle cache grace timer');
undef $grace_client;

my ($trim_client, $trim_buffer) = new_session();
run_stream($trim_client, $trim_buffer, 11, 'warm-trim', 0);
sleep 1.2;
is(run_stream($trim_client, $trim_buffer, 13, 'reuse-after-trim', 0),
    'reuse-after-trim', 'session creates a stream after idle cache trim');
undef $trim_client;

my $drain_client = stream('127.0.0.1:' . port(8080));
my $drain_buffer = '';
$drain_client->write(auth_prefix('test-password')
    . frame(CMD_SETTINGS, 0, "v=2\n")
    . frame(CMD_SYN, 21)
    . frame(CMD_FIN, 21));
my $drain_cmd;
while (1) {
    ($drain_cmd) = read_frame($drain_client, \$drain_buffer);
    last if $drain_cmd == 10;  # SERVER_SETTINGS
}
is($drain_cmd, 10,
    'connection-level output drains after the last stream closes');
sleep 1.2;
undef $drain_client;

sleep 0.2;
my $log = $t->read_file('access.log');
my @trims = $log =~ /^(\d+)$/mg;
is_deeply(\@trims, [0, 1, 1],
    'cache trim is rearmed when connection-level output drains');
