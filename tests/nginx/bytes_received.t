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
    auth_prefix frame socks5_ipv4_addr
    read_anytls_push tcp_echo_socket tcp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $tcp_server = tcp_echo_socket();
my $tcp_port = $tcp_server->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(3)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format atls 'rcv=$bytes_received snt=$bytes_sent';

    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/access.log atls;

        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

$t->run_daemon(sub { tcp_echo_daemon($tcp_server) });
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));
my $payload = 'x' x 1000;

# client bytes on the main anytls path, all counted into s->received:
#   34  auth_prefix (sha256 + 2-byte len)
#   11  settings frame (7 header + "v=2\n")
#    7  SYN frame
# 1014  PUSH frame (7 header + 7 SOCKS5 addr + 1000 payload)
#    7  FIN frame
# = 1073
$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->write(frame(CMD_SYN, 1, ''));
$client->write(frame(CMD_PUSH, 1,
    socks5_ipv4_addr('127.0.0.1', $tcp_port) . $payload));

is(read_anytls_push($client, 1), $payload, 'echo payload received');

$client->write(frame(CMD_FIN, 1, ''));
$client->socket()->close();

my $log = '';
for (1 .. 100) {
    $log = $t->read_file('access.log');
    last if $log =~ /rcv=/;
    usleep(20_000);
}

like($log, qr/rcv=1073/, 'bytes_received counts every client byte');
my ($snt) = $log =~ /snt=(\d+)/;
ok($snt && $snt >= 1000, "bytes_sent counts server bytes ($snt)");
