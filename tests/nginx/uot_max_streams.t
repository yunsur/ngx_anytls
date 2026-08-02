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
    auth_prefix frame uot_v2_connect_open uot_v2_connect_datagram
    udp_echo_socket udp_echo_daemon
/;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $udp_server = udp_echo_socket();
my $udp_port = $udp_server->sockport();

my $t = Test::Nginx->new()->has(qw/stream/)->plan(3)
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
        anytls_fallback_proxy_protocol on;
        anytls_max_uot_streams 2;
    }
}

EOF

$t->run_daemon(sub { udp_echo_daemon($udp_server) });
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));

$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));

# stream 1 opens but closes BEFORE creating its UDP socket (no datagram
# sent): its cap slot must be released, not leaked
my $s1 = 11;
$client->write(frame(CMD_SYN, $s1, ''));
$client->write(frame(CMD_PUSH, $s1,
    uot_v2_connect_open('127.0.0.1', $udp_port)));
$client->write(frame(CMD_FIN, $s1, ''));

# streams 2 and 3 fit under the cap (stream 1's slot was released)
my $s2 = 12;
my $s3 = 13;
my $payload = 'uot cap echo';

for my $sid ($s2, $s3) {
    $client->write(frame(CMD_SYN, $sid, ''));
    $client->write(frame(CMD_PUSH, $sid,
        uot_v2_connect_open('127.0.0.1', $udp_port)));
    $client->write(frame(CMD_PUSH, $sid, uot_v2_connect_datagram($payload)));
}

my $pending = '';
my $r2 = read_push($client, \$pending, $s2);
my ($len2, $body2) = unpack('n a*', $r2);
is($body2, $payload,
    'UoT stream opens after a pre-UDP FIN released its slot');

my $r3 = read_push($client, \$pending, $s3);
my ($len3, $body3) = unpack('n a*', $r3);
is($body3, $payload, 'second UoT stream under cap echoes');

# stream 4 exceeds the cap: the server rejects the stream with a SYNACK
# error and the connection stays alive
my $s4 = 14;
$client->write(frame(CMD_SYN, $s4, ''));
$client->write(frame(CMD_PUSH, $s4,
    uot_v2_connect_open('127.0.0.1', $udp_port)));
$client->write(frame(CMD_PUSH, $s4, uot_v2_connect_datagram($payload)));

my $rejected = read_fin($client, \$pending, $s4);
ok($rejected, 'stream beyond anytls_max_uot_streams is rejected');

$client->write(frame(CMD_FIN, $s2, ''));
$client->write(frame(CMD_FIN, $s3, ''));

# buffer across calls so frames sharing one TCP segment are not lost
sub read_push {
    my ($client, $pending, $stream_id) = @_;
    while (1) {
        my $frame = next_frame($client, $pending);
        next if !defined $frame;
        my ($cmd, $sid, $data) = @$frame;
        return $data if $cmd == CMD_PUSH && $sid == $stream_id;
    }
}

sub read_fin {
    my ($client, $pending, $stream_id) = @_;
    my $deadline = time() + 2;
    while (time() < $deadline) {
        my $frame = next_frame($client, $pending);
        if (defined $frame) {
            my ($cmd, $sid, $data) = @$frame;
            return 1 if $cmd == CMD_FIN && $sid == $stream_id;
            # non-empty SYNACK = stream-level error => rejected
            return 1 if $cmd == 7 && $sid == $stream_id && length($data);
            return 0 if $cmd == 7 && $sid == $stream_id;
        }
    }
    return 0;
}

sub next_frame {
    my ($client, $pending) = @_;

    while (length($$pending) < 7) {
        my $chunk = $client->read();
        return undef if !defined $chunk || $chunk eq '';
        $$pending .= $chunk;
    }

    my ($cmd, $sid, $len) = unpack('C N n', substr($$pending, 0, 7));
    while (length($$pending) < 7 + $len) {
        my $chunk = $client->read();
        return undef if !defined $chunk || $chunk eq '';
        $$pending .= $chunk;
    }

    my $data = substr($$pending, 7, $len);
    substr($$pending, 0, 7 + $len, '');
    return [$cmd, $sid, $data];
}
