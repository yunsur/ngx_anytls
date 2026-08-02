#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
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
        anytls_user alice secret-alice;
        anytls_user bob secret-bob;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }
}

EOF

$t->run();

my $p = port(8080);

# 1. first user authenticates
ok(auth_ok($p, 'secret-alice'), 'first anytls_user password authenticates');

# 2. second user authenticates
ok(auth_ok($p, 'secret-bob'), 'second anytls_user password authenticates');

# 3. wrong password falls back (unreachable fallback closes connection)
my $c3 = connect_anytls($p);
$c3->print(auth_prefix('wrong-password'));
$c3->print(frame(CMD_SETTINGS, 0, "v=2\n"));
my $resp3 = <$c3>;
ok(!defined($resp3) || $resp3 eq '',
    'wrong password does not authenticate (connection closed)');
$c3->close();

sub connect_anytls {
    my ($port) = @_;
    my $c = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$port", Proto => 'tcp', Timeout => 3)
        or die "connect $port: $!\n";
    $c->autoflush(1);
    return $c;
}

sub auth_ok {
    my ($port, $password) = @_;
    my $c = connect_anytls($port);
    $c->print(auth_prefix($password));
    $c->print(frame(CMD_SETTINGS, 0, "v=2\n"));
    $c->sockopt(SO_RCVTIMEO, 3);

    my $buf = '';
    my $deadline = time() + 3;

    while (time() < $deadline) {
        my $n = sysread($c, my $chunk, 4096);
        last if !defined $n || $n == 0;
        $buf .= $chunk;

        while (length($buf) >= 7) {
            my ($cmd, $sid, $len) = unpack('C N n', substr($buf, 0, 7));
            if (length($buf) < 7 + $len) {
                last;
            }
            return 1 if $cmd == 10;   # SERVER_SETTINGS
            substr($buf, 0, 7 + $len, '');
        }
    }

    $c->close();
    return 0;
}
