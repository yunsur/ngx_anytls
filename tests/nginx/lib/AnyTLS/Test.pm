package AnyTLS::Test;

use warnings;
use strict;

use Digest::SHA qw/ sha256 /;
use Exporter qw/ import /;
use IO::Socket::INET;
use Time::HiRes qw/ sleep /;

our @EXPORT_OK = qw/
    CMD_SYN CMD_PUSH CMD_FIN CMD_SETTINGS
    auth_prefix frame socks5_domain_addr socks5_ipv4_addr
    uot_v2_packet_open uot_v2_connect_open
    uot_ipv4_packet uot_domain_packet uot_v2_connect_datagram
    read_anytls_push parse_uot_ipv4_packet
    udp_echo_socket udp_echo_daemon udp_log_daemon dns_socket dns_daemon
    tcp_echo_socket tcp_echo_daemon
/;

use constant {
    CMD_SYN      => 1,
    CMD_PUSH     => 2,
    CMD_FIN      => 3,
    CMD_SETTINGS => 4,
};

sub auth_prefix {
    my ($password) = @_;
    return sha256($password) . pack('n', 0);
}

sub frame {
    my ($cmd, $stream_id, $data) = @_;
    $data = '' if !defined $data;
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
    my ($host, $port) = @_;
    return socks5_domain_addr('sp.v2.udp-over-tcp.arpa', 443)
        . pack('C', 0)
        . socks5_ipv4_addr($host, $port);
}

sub uot_v2_connect_open {
    my ($host, $port) = @_;
    return socks5_domain_addr('sp.v2.udp-over-tcp.arpa', 443)
        . pack('C', 1)
        . socks5_ipv4_addr($host, $port);
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

sub uot_v2_connect_datagram {
    my ($payload) = @_;
    return pack('n', length($payload)) . $payload;
}

sub read_anytls_push {
    my ($client, $stream_id) = @_;
    my $buffer = '';

    while (1) {
        my $header = _read_exact($client, \$buffer, 7);
        my ($cmd, $sid, $len) = unpack('C N n', $header);
        my $data = _read_exact($client, \$buffer, $len);

        next if $cmd != CMD_PUSH || $sid != $stream_id;

        return $data;
    }
}

sub _read_exact {
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
    my $socket = IO::Socket::INET->new(
        Proto => 'udp',
        LocalHost => '127.0.0.1',
        LocalPort => 0,
    );

    die "failed to listen on UDP port: $!" if !defined $socket;
    return $socket;
}

sub udp_echo_daemon {
    my ($server) = @_;

    while (1) {
        my $peer = recv($server, my $buf, 65536, 0);
        next if !defined $peer;
        send($server, $buf, 0, $peer);
    }
}

sub udp_log_daemon {
    my ($server, $log_path) = @_;

    while (1) {
        my $peer = recv($server, my $buf, 65536, 0);
        next if !defined $peer;

        if (open my $log, '>>', $log_path) {
            print $log "$buf\n";
            close $log;
        }

        send($server, $buf, 0, $peer);
    }
}

sub tcp_echo_daemon {
    my ($server) = @_;

    while (my $client = $server->accept()) {
        while (1) {
            my $buf = '';
            my $n = sysread($client, $buf, 65536);
            last if !defined $n || $n == 0;
            _write_all($client, $buf);
        }
        close $client;
    }
}

sub tcp_echo_socket {
    my $socket = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalHost => '127.0.0.1',
        LocalPort => 0,
        Listen => 5,
        Reuse => 1,
    );

    die "failed to listen on TCP port: $!" if !defined $socket;
    return $socket;
}

sub dns_socket {
    my $socket = IO::Socket::INET->new(
        Proto => 'udp',
        LocalHost => '127.0.0.1',
        LocalPort => 0,
    );

    die "failed to listen on DNS UDP port: $!" if !defined $socket;
    return $socket;
}

sub dns_daemon {
    my ($server, $records) = @_;

    while (1) {
        my $peer = recv($server, my $query, 512, 0);
        next if !defined $peer;

        my $response = _dns_response($query, $records);
        next if !defined $response;

        send($server, $response, 0, $peer);
    }
}

sub _dns_response {
    my ($query, $records) = @_;

    return undef if length($query) < 12;

    my ($id, $flags, $qdcount) = unpack('n n n', substr($query, 0, 6));
    return undef if $qdcount < 1;

    my $off = 12;
    my @labels;
    while ($off < length($query)) {
        my $len = unpack('C', substr($query, $off, 1));
        $off++;
        last if $len == 0;
        return undef if $off + $len > length($query);
        push @labels, substr($query, $off, $len);
        $off += $len;
    }

    return undef if $off + 4 > length($query);

    my $question = substr($query, 12, $off + 4 - 12);
    my ($qtype, $qclass) = unpack('n n', substr($query, $off, 4));
    my $name = lc join('.', @labels);

    if (defined $records->{__log_path}) {
        if (open my $log, '>>', $records->{__log_path}) {
            print $log "$name\n";
            close $log;
        }
    }

    return undef if exists $records->{$name} && !defined $records->{$name};

    my $record = $records->{$name};
    if (defined $record && $record =~ /^DELAY:([0-9.]+):(\d+\.\d+\.\d+\.\d+)$/) {
        sleep($1);
        $record = $2;
    }

    if (!exists $records->{$name} || $record eq 'NXDOMAIN'
        || $qtype != 1 || $qclass != 1)
    {
        return pack('n n n n n n', $id, 0x8183, 1, 0, 0, 0) . $question;
    }

    my $answer = pack('n n n N n C4',
        0xc00c, 1, 1, 30, 4, split(/\./, $record));

    return pack('n n n n n n', $id, 0x8180, 1, 1, 0, 0)
        . $question . $answer;
}

sub _write_all {
    my ($fh, $buf) = @_;
    my $offset = 0;

    while ($offset < length($buf)) {
        my $written = syswrite($fh, $buf, length($buf) - $offset, $offset);
        last if !defined $written || $written == 0;
        $offset += $written;
    }
}

1;
