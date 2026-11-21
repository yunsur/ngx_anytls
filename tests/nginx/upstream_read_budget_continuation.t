#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use IO::Socket::INET;
use Test::More;

BEGIN {
    unshift @INC, $ENV{TEST_NGINX_LIB} if defined $ENV{TEST_NGINX_LIB};
}

use AnyTLS::Test qw/
    CMD_SYN CMD_PUSH CMD_SETTINGS auth_prefix frame socks5_ipv4_addr
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $upstream = IO::Socket::INET->new(
    Proto => 'tcp', LocalHost => '127.0.0.1', LocalPort => 0,
    Listen => 16, Reuse => 1) or die "listen failed: $!";
my $upstream_port = $upstream->sockport();
my $blocks = 40;
my $block_size = 16377;
my $wanted = $blocks * $block_size;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(3)
    ->write_file_expand('nginx.conf', <<EOF);

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

$t->run_daemon(sub {
    $SIG{CHLD} = 'IGNORE';
    pipe(my $ready_r, my $ready_w) or die "ready pipe failed: $!";
    pipe(my $start_r, my $start_w) or die "start pipe failed: $!";

    for (1 .. 2) {
        my $peer = $upstream->accept() or die "accept failed: $!";
        my $pid = fork();
        die "fork failed: $!" if !defined $pid;
        if ($pid == 0) {
            close $upstream;
            close $ready_r;
            close $start_w;
            my $marker = '';
            while (length($marker) < 3) {
                my $n = sysread($peer, $marker, 3 - length($marker),
                    length($marker));
                exit 1 if !defined $n || $n == 0;
            }
            syswrite($ready_w, 'R') == 1 or exit 1;
            sysread($start_r, my $start, 1) == 1 or exit 1;

            my $fill = $marker =~ /two/ ? 'B' : 'A';
            my $chunk = $fill x $block_size;
            for (1 .. $blocks) {
                my $offset = 0;
                while ($offset < length($chunk)) {
                    my $n = syswrite($peer, $chunk,
                        length($chunk) - $offset, $offset);
                    exit 1 if !defined $n || $n == 0;
                    $offset += $n;
                }
            }
            close $peer;
            exit 0;
        }
        close $peer;
    }

    close $ready_w;
    close $start_r;
    my $ready = '';
    while (length($ready) < 2) {
        my $n = sysread($ready_r, $ready, 2 - length($ready),
            length($ready));
        die "upstream readiness failed: $!" if !defined $n || $n == 0;
    }
    syswrite($start_w, 'GG') == 2 or die "upstream start failed: $!";
    close $ready_r;
    close $start_w;
    sleep 1 while 1;
});
$t->run();

my $client = stream('127.0.0.1:' . port(8080));
$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
for my $spec ([1, 'one'], [3, 'two']) {
    my ($id, $marker) = @$spec;
    $client->write(frame(CMD_SYN, $id));
    $client->write(frame(CMD_PUSH, $id,
        socks5_ipv4_addr('127.0.0.1', $upstream_port) . $marker));
}

my %received = (1 => '', 3 => '');
my %expected = (1 => 'A', 3 => 'B');
my $payloads_valid = 1;
my $buffer = '';
while (length($received{1}) < $wanted || length($received{3}) < $wanted) {
    while (length($buffer) < 7) {
        my $chunk = $client->read();
        die 'unexpected EOF waiting for upstream data' if !defined $chunk;
        $buffer .= $chunk;
    }
    my ($cmd, $id, $len) = unpack('C N n', substr($buffer, 0, 7));
    while (length($buffer) < 7 + $len) {
        my $chunk = $client->read();
        die 'unexpected EOF in upstream frame' if !defined $chunk;
        $buffer .= $chunk;
    }
    my $data = substr($buffer, 7, $len);
    substr($buffer, 0, 7 + $len, '');
    next if $cmd != CMD_PUSH || !exists $received{$id};
    $payloads_valid = 0
        if $data ne $expected{$id} x length($data);
    $received{$id} .= $data;
}

is(length($received{1}), $wanted,
    'first stream receives more than 32 full upstream read blocks');
is(length($received{3}), $wanted,
    'second stream also receives all continuously available data');
ok($payloads_valid,
    'concurrent upstream payloads remain assigned to their streams');
