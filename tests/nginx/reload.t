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

my $echo = tcp_echo_socket();
my $echo_port = $echo->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(2)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8080;

        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
    }
}

EOF

$t->run_daemon(sub { tcp_echo_daemon($echo) });
$t->run();
usleep(100_000);

my $port = port(8080);

# session before reload
my $c1 = stream("127.0.0.1:$port");
my $sid1 = 41;
my $p1 = 'before reload';

$c1->write(auth_prefix('test-password'));
$c1->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$c1->write(frame(CMD_SYN, $sid1, ''));
$c1->write(frame(CMD_PUSH, $sid1, socks5_ipv4_addr('127.0.0.1', $echo_port)));
$c1->write(frame(CMD_PUSH, $sid1, $p1));

is(read_anytls_push($c1, $sid1), $p1, 'session echoes before reload');

# close the pre-reload session so the old worker exits with no open
# sockets (nginx graceful reload drops idle stream connections on the old
# worker, which is not a module concern)
$c1->write(frame(CMD_FIN, $sid1, ''));
$c1->{_socket}->close();
usleep(100_000);

$t->reload();
usleep(100_000);

# a brand-new session works after reload
my $c2 = stream("127.0.0.1:$port");
my $sid2 = 42;
my $p2 = 'after reload';
$c2->write(auth_prefix('test-password'));
$c2->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$c2->write(frame(CMD_SYN, $sid2, ''));
$c2->write(frame(CMD_PUSH, $sid2, socks5_ipv4_addr('127.0.0.1', $echo_port)));
$c2->write(frame(CMD_PUSH, $sid2, $p2));
is(read_anytls_push($c2, $sid2), $p2,
    'new session authenticates and echoes after reload');

$c2->write(frame(CMD_FIN, $sid2, ''));
$c2->{_socket}->close();
