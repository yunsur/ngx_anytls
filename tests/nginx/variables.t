#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::More;
use Time::HiRes qw/ sleep usleep /;
use IO::Socket::INET;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use AnyTLS::Test qw/ CMD_SETTINGS auth_prefix frame /;
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(4)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format atls '$anytls_user $anytls_version $anytls_auth';

    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/access.log atls;

        anytls on;
        anytls_user alice secret-alice;
        anytls_handshake_timeout 200ms;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

$t->run();
usleep(100_000);

# 1. authenticated connection: user name + version logged
my $c1 = auth_connect(port(8080), 'secret-alice');
ok($c1, 'authenticated connection completes auth handshake');
$c1->close() if $c1;

# 2. failed auth goes to fallback (unreachable -> closed)
my $c2 = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . port(8080), Proto => 'tcp', Timeout => 2);
$c2->print(auth_prefix('wrong-password'));
$c2->print(frame(CMD_SETTINGS, 0, "v=2\n"));
$c2->close();

# 3. idle auth connection is closed by handshake timeout
my $c3 = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . port(8080), Proto => 'tcp', Timeout => 2);

sleep 0.5;
$c3->close() if $c3;

my $log = $t->read_file('access.log');

like($log, qr/^alice 2 ok$/m,
    'authenticated connection logged with user, version, auth status');
like($log, qr/^- - fallback$/m,
    'auth failure fallback logged with fallback status');
like($log, qr/^- - timeout$/m,
    'handshake timeout logged with timeout status');

sub auth_connect {
    my ($port, $password) = @_;
    my $c = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$port", Proto => 'tcp', Timeout => 2)
        or return 0;
    $c->autoflush(1);
    $c->print(auth_prefix($password));
    $c->print(frame(CMD_SETTINGS, 0, "v=2\n"));
    $c->sockopt(SO_RCVTIMEO, 2);

    my $buf = '';
    my $deadline = time() + 2;
    while (time() < $deadline) {
        my $n = sysread($c, my $chunk, 4096);
        last if !defined $n || $n == 0;
        $buf .= $chunk;
        while (length($buf) >= 7) {
            my ($cmd, $sid, $len) = unpack('C N n', substr($buf, 0, 7));
            return $c if $cmd == 10;   # SERVER_SETTINGS => authenticated
            last if length($buf) < 7 + $len;
            substr($buf, 0, 7 + $len, '');
        }
    }
    $c->close();
    return 0;
}
