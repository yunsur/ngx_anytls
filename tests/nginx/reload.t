#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use Time::HiRes qw/ time usleep /;

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

sub wait_for_fin {
    my ($client, $stream_id) = @_;
    my $buffer = '';
    my $deadline = time() + 10;

    while (time() < $deadline) {
        while (length($buffer) < 7) {
            my $chunk = $client->read();
            return 0 if !defined $chunk;
            $buffer .= $chunk;
        }

        my ($cmd, $sid, $len) = unpack('C N n', substr($buffer, 0, 7));
        while (length($buffer) < 7 + $len) {
            my $chunk = $client->read();
            return 0 if !defined $chunk;
            $buffer .= $chunk;
        }

        substr($buffer, 0, 7 + $len, '');
        return 1 if $cmd == CMD_FIN && $sid == $stream_id;
    }

    return 0;
}

sub wait_for_worker_exit {
    my ($test, $pid) = @_;
    my $deadline = time() + 10;

    while (time() < $deadline) {
        return 1
            if $test->read_file('error.log')
                =~ /worker process \Q$pid\E exited with code 0/;
        usleep(10_000);
    }

    return 0;
}

my $echo = tcp_echo_socket();
my $echo_port = $echo->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(5)
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

# close the pre-reload stream and wait until nginx has released its
# upstream connection before closing the session
$c1->write(frame(CMD_FIN, $sid1, ''));
ok(wait_for_fin($c1, $sid1), 'pre-reload stream closes cleanly');
$c1->{_socket}->close();

my @worker_pids = $t->read_file('error.log') =~ /start worker process (\d+)/g;
my $old_worker_pid = $worker_pids[-1]
    // die 'unable to identify pre-reload worker';
$t->reload();
ok(wait_for_worker_exit($t, $old_worker_pid),
    'pre-reload worker exits cleanly');

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
ok(wait_for_fin($c2, $sid2), 'post-reload stream closes cleanly');
$c2->{_socket}->close();
