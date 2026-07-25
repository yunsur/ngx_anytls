#!/usr/bin/perl

use warnings;
use strict;

use Digest::SHA qw/ sha256 /;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw/ usleep /;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

use constant {
    CMD_SYN      => 1,
    CMD_PUSH     => 2,
    CMD_FIN      => 3,
    CMD_SETTINGS => 4,
};

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
        anytls_password test-password;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

my $udp_server = udp_echo_socket();
my $udp_port = $udp_server->sockport();

$t->run_daemon(\&udp_echo_daemon);
$t->run();
usleep(100_000);

my $client = stream('127.0.0.1:' . port(8080));
my $stream_id = 9;
my $payload = 'uot ipv4 echo';

$client->write(auth_prefix('test-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->write(frame(CMD_SYN, $stream_id, ''));
$client->write(frame(CMD_PUSH, $stream_id, uot_v2_packet_open()));
$client->write(frame(CMD_PUSH, $stream_id,
    uot_ipv4_packet('127.0.0.1', $udp_port, $payload)));

my $response = read_anytls_push($client, $stream_id);
my ($host, $port, $body) = parse_uot_ipv4_packet($response);

is($host, '127.0.0.1', 'UoT IPv4 response source is localhost');
is($port, $udp_port, 'UoT IPv4 response source port matches UDP upstream');
is($body, $payload, 'UoT IPv4 packet receives UDP echo response');

$client->write(frame(CMD_FIN, $stream_id, ''));

sub auth_prefix {
    my ($password) = @_;
    return sha256($password) . pack('n', 0);
}

sub frame {
    my ($cmd, $stream_id, $data) = @_;
    return pack('C N n', $cmd, $stream_id, length($data)) . $data;
}

sub socks5_domain_addr {
    my ($domain, $port) = @_;
    return pack('C C', 3, length($domain)) . $domain . pack('n', $port);
}

sub socks5_ipv4_addr {
    my ($host, $port) = @_;
    return pack('C C4 n', 1, split(/\./, $host), $port);
}

sub uot_v2_packet_open {
    return socks5_domain_addr('sp.v2.udp-over-tcp.arpa', 443)
        . pack('C', 0)
        . socks5_ipv4_addr('127.0.0.1', $udp_port);
}

sub uot_ipv4_packet {
    my ($host, $port, $payload) = @_;
    return pack('C C4 n n', 0, split(/\./, $host), $port, length($payload))
        . $payload;
}

sub uot_domain_packet {
    my ($domain, $port, $payload) = @_;
    return pack('C C', 2, length($domain)) . $domain
        . pack('n n', $port, length($payload))
        . $payload;
}

sub read_anytls_push {
    my ($client, $stream_id) = @_;
    my $buffer = '';

    while (1) {
        my $header = read_exact($client, \$buffer, 7);
        my ($cmd, $sid, $len) = unpack('C N n', $header);
        my $data = read_exact($client, \$buffer, $len);

        next if $cmd != CMD_PUSH || $sid != $stream_id;

        return $data;
    }
}

sub read_exact {
    my ($client, $buffer, $len) = @_;

    while (length($$buffer) < $len) {
        my $chunk = $client->read();
        die "unexpected EOF while reading AnyTLS frame" if !defined $chunk;
        $$buffer .= $chunk;
    }

    my $wanted = substr($$buffer, 0, $len);
    substr($$buffer, 0, $len) = '';

    return $wanted;
}

sub parse_uot_ipv4_packet {
    my ($packet) = @_;
    my ($atyp, @rest) = unpack('C C4 n n a*', $packet);
    die "unexpected UoT atyp: $atyp" if $atyp != 0;

    return (join('.', @rest[0 .. 3]), $rest[4], $rest[6]);
}

sub udp_echo_socket {
    my $server = IO::Socket::INET->new(
        Proto => 'udp',
        LocalHost => '127.0.0.1',
        LocalPort => 0,
    )
        or die "failed to listen on UDP port: $!";

    return $server;
}

sub udp_echo_daemon {
    while (1) {
        my $peer = recv($udp_server, my $buf, 65536, 0);
        next if !defined $peer;
        send($udp_server, $buf, 0, $peer);
    }
}
