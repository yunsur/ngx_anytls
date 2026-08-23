#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin/lib";

use IO::Select;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw/ usleep /;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use AnyTLS::Test qw/ CMD_SETTINGS auth_prefix frame /;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $greeting = 'greetings from the fallback upstream';
my $payload = 'y' x 1000;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(3)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format atls 'rcv=$bytes_received snt=$bytes_sent';

    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/access.log atls;

        anytls on;
        anytls_user test test-password;
        anytls_fallback 127.0.0.1:8081;
        anytls_fallback_proxy_protocol off;
    }
}

EOF

$t->run_daemon(\&fallback_daemon);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

my $client = stream('127.0.0.1:' . port(8080));

# client bytes after auth failure, all counted into s->received:
#   34  auth_prefix (sha256 + 2-byte len)      -> main read loop
#   11  settings frame (7 header + "v=2\n")    -> main read loop
# 1000  raw relay payload                      -> fallback relay
# = 1045
$client->write(auth_prefix('wrong-password'));
$client->write(frame(CMD_SETTINGS, 0, "v=2\n"));
$client->write($payload);

is($client->read(), $greeting, 'fallback relays to the upstream and back');

$client->socket()->close();

my $log = '';
for (1 .. 100) {
    $log = $t->read_file('access.log');
    last if $log =~ /rcv=/;
    usleep(20_000);
}

like($log, qr/rcv=1045/, 'bytes_received counts client bytes in fallback mode');
my ($snt) = $log =~ /snt=(\d+)/;
ok($snt && $snt >= length($greeting),
    "bytes_sent counts bytes relayed to the client ($snt)");

sub fallback_daemon {
    my $server = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalHost => '127.0.0.1',
        LocalPort => port(8081),
        Listen => 5,
        Reuse => 1,
    )
        or die "failed to listen on fallback port: $!";

    my $select = IO::Select->new($server);

    while (1) {
        my @ready = $select->can_read(0.1);
        foreach my $fh (@ready) {
            if ($fh == $server) {
                my $client = $server->accept()
                    or next;

                # one-shot upstream: greet, then drain until EOF
                my $offset = 0;
                while ($offset < length($greeting)) {
                    my $written = syswrite($client, $greeting,
                        length($greeting) - $offset, $offset);
                    last if !defined $written || $written == 0;
                    $offset += $written;
                }
                while (1) {
                    my $buf = '';
                    my $n = sysread($client, $buf, 65536);
                    last if !defined $n || $n == 0;
                }
                close $client;
            }
        }
    }
}
