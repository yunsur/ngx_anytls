#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::More;
use Time::HiRes qw/ usleep /;
use IO::Socket::INET;
use IO::Socket::SSL;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use AnyTLS::Test qw/
    CMD_SYN CMD_PUSH CMD_FIN CMD_SETTINGS
    auth_prefix frame socks5_ipv4_addr
    read_anytls_push tcp_echo_socket tcp_echo_daemon
/;
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $echo = tcp_echo_socket();
my $echo_port = $echo->sockport();

my $t = Test::Nginx->new()->has(qw/stream ssl/)->plan(2);

my $testdir = $t->{_testdir};
system("openssl genrsa -out $testdir/localhost.key 2048 "
    . ">>$testdir/openssl.out 2>&1") == 0 or die "genrsa: $!\n";
system("openssl req -x509 -new -subj /CN=localhost/ "
    . "-out $testdir/localhost.crt -key $testdir/localhost.key "
    . ">>$testdir/openssl.out 2>&1") == 0 or die "req: $!\n";

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8443 ssl;
        ssl_protocols TLSv1.3;
        ssl_certificate %%TESTDIR%%/localhost.crt;
        ssl_certificate_key %%TESTDIR%%/localhost.key;

        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
    }
}

EOF

$t->run_daemon(sub { tcp_echo_daemon($echo) });
$t->run();
usleep(100_000);

# TLS 1.3 session: record layer differs from 1.2, auth and stream data
# must still work
my $client = IO::Socket::SSL->new(
    PeerAddr        => '127.0.0.1:' . port(8443),
    SSL_verify_mode => SSL_VERIFY_NONE,
    SSL_version     => 'TLSv13',
    Timeout         => 5,
);
ok($client, 'TLS 1.3 handshake succeeds');

my $payload = 'tls13 data path';
my $stream_id = 31;

$client->print(auth_prefix('test-password'));
$client->print(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->print(frame(CMD_SYN, $stream_id, ''));
$client->print(frame(CMD_PUSH, $stream_id,
    socks5_ipv4_addr('127.0.0.1', $echo_port)));
$client->print(frame(CMD_PUSH, $stream_id, $payload));

my $response = read_push_tls($client, $stream_id);
is($response, $payload, 'data echoes over TLS 1.3 session');

$client->print(frame(CMD_FIN, $stream_id, ''));
$client->close();

# read_anytls_push uses the parameter-less read() of Test::Nginx::Stream,
# which does not work on IO::Socket::SSL; read frames via sysread instead
sub read_push_tls {
    my ($sock, $wanted_sid) = @_;
    my $buf = '';

    while (1) {
        while (length($buf) < 7) {
            my $n = sysread($sock, my $chunk, 4096);
            die "EOF while reading frame\n" if !defined $n || $n == 0;
            $buf .= $chunk;
        }

        my ($cmd, $sid, $len) = unpack('C N n', substr($buf, 0, 7));
        while (length($buf) < 7 + $len) {
            my $n = sysread($sock, my $chunk, 4096);
            die "EOF while reading frame data\n" if !defined $n || $n == 0;
            $buf .= $chunk;
        }

        my $data = substr($buf, 7, $len);
        substr($buf, 0, 7 + $len, '');
        return $data if $cmd == 2 && $sid == $wanted_sid;
    }
}
