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
    auth_prefix frame uot_v2_packet_open uot_domain_packet
    read_anytls_push parse_uot_ipv4_packet
    udp_echo_socket udp_log_daemon dns_socket dns_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;
my $seed = defined $ENV{ANYTLS_FUZZ_SEED}
    ? int($ENV{ANYTLS_FUZZ_SEED}) : 0x554f5402;
srand($seed);

sub write_fragmented {
    my ($client, $data) = @_;

    while (length($data) != 0) {
        my $len = 1 + int(rand(59));
        $len = length($data) if $len > length($data);
        $client->write(substr($data, 0, $len, ''));
    }
}


my $dns = dns_socket();
my $dns_port = $dns->sockport();
my $udp = udp_echo_socket();
my $udp_port = $udp->sockport();
my $t = Test::Nginx->new()->has(qw/stream/)->plan(4)
    ->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%
daemon off;
events { }
stream {
    %%TEST_GLOBALS_STREAM%%
    resolver 127.0.0.1:$dns_port valid=5s ipv6=off;
    resolver_timeout 1s;
    server {
        listen 127.0.0.1:8080;
        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol off;
        anytls_uot_pending_packets 4;
        anytls_uot_pending_bytes 64k;
    }
}
EOF

my $udp_log = $t->testdir() . '/udp.log';
$t->run_daemon(sub {
    dns_daemon($dns, {
        'slow.test' => 'DELAY:0.2:127.0.0.1',
        'bad.test' => 'NXDOMAIN',
    });
});
$t->run_daemon(sub { udp_log_daemon($udp, $udp_log) });
$t->run();

my $client = stream('127.0.0.1:' . port(8080));
my $id = 41;
$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
write_fragmented($client, frame(CMD_SYN, $id)
    . frame(CMD_PUSH, $id, uot_v2_packet_open('127.0.0.1', $udp_port)));

for my $n (1 .. 10) {
    write_fragmented($client, frame(CMD_PUSH, $id,
        uot_domain_packet('slow.test', $udp_port, "slow-$n")));
}
my (undef, undef, $first) = parse_uot_ipv4_packet(
    read_anytls_push($client, $id));
like($first, qr/^slow-/, 'delayed successful domain queue flushes');

usleep(400_000);
open my $log, '<', $udp_log or die "open UDP log: $!";
my @initial = <$log>;
close $log;
chomp @initial;
ok(scalar(@initial) <= 4,
    'packets beyond the configured pending queue cap are dropped');

for my $n (1 .. 10) {
    write_fragmented($client, frame(CMD_PUSH, $id,
        uot_domain_packet('bad.test', $udp_port, "bad-$n")));
}
usleep(200_000);
write_fragmented($client, frame(CMD_PUSH, $id,
    uot_domain_packet('slow.test', $udp_port, 'after-failure')));

my $recovered = 0;
for (1 .. 12) {
    my (undef, undef, $payload) = parse_uot_ipv4_packet(
        read_anytls_push($client, $id));
    if ($payload eq 'after-failure') {
        $recovered = 1;
        last;
    }
}
ok($recovered, 'resolver failure drops its domain and later packets continue');

$client->write(frame(CMD_FIN, $id));
$client->socket()->close();
pass('closing a UoT stream with churned pending queues succeeds');
