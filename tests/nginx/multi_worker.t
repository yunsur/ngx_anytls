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
    uot_v2_connect_open uot_v2_connect_datagram
    udp_echo_socket udp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $udp_server = udp_echo_socket();
my $udp_port = $udp_server->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(1)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
worker_processes 4;

events {
    worker_connections 1024;
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

$t->run_daemon(sub { udp_echo_daemon($udp_server) });
$t->run();
usleep(100_000);

my $port = port(8080);
my $workers = 8;
my $payload = 'multi-worker udp echo';

my @results;
my @pids;

# N concurrent clients across the worker pool, each with its own session
# and UoT stream
for my $i (1 .. $workers) {
    my $pid = fork();
    if ($pid == 0) {
        my $sid = 100 + $i;
        my $client = stream("127.0.0.1:$port");

        $client->write(auth_prefix('test-password'));
        $client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
        $client->write(frame(CMD_SYN, $sid, ''));
        $client->write(frame(CMD_PUSH, $sid,
            uot_v2_connect_open('127.0.0.1', $udp_port)));
        $client->write(frame(CMD_PUSH, $sid,
            uot_v2_connect_datagram($payload . $i)));

        my $ok = 0;
        my $deadline = time() + 5;
        my $buf = '';
        while (time() < $deadline) {
            my $data = $client->read();
            last if !defined $data || $data eq '';
            $buf .= $data;
            while (length($buf) >= 7) {
                my ($cmd, $rsid, $len) = unpack('C N n', substr($buf, 0, 7));
                last if length($buf) < 7 + $len;
                my $body = substr($buf, 7, $len);
                substr($buf, 0, 7 + $len, '');
                if ($cmd == 2 && $rsid == $sid) {
                    my (undef, $echo) = unpack('n a*', $body);
                    $ok = 1 if $echo eq $payload . $i;
                }
            }
            last if $ok;
        }
        $client->write(frame(CMD_FIN, $sid, ''));
        $client->{_socket}->close();
        exit($ok ? 0 : 1);
    }
    push @pids, $pid;
}

for my $pid (@pids) {
    waitpid($pid, 0);
    push @results, $? == 0;
}

ok(!grep { !$_ } @results,
    "all $workers concurrent sessions across workers echo correctly");
