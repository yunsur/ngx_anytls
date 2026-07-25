#!/usr/bin/perl

use warnings;
use strict;

use IO::Select;
use IO::Socket::INET;
use Test::More;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(1)
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
        anytls_fallback 127.0.0.1:8081;
        anytls_fallback_proxy_protocol off;
    }
}

EOF

$t->run_daemon(\&fallback_daemon);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

my $payload = ('x' x 24) . ' replay me';

is(stream('127.0.0.1:' . port(8080))->io($payload, length => length($payload)),
    $payload, 'auth failure fallback replays buffered bytes');

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
                fallback_handle_client($client);
                close $client;
            }
        }
    }
}

sub fallback_handle_client {
    my ($client) = @_;
    my $buf = '';

    my $n = sysread($client, $buf, 65536);
    return if !defined $n || $n == 0;

    my $offset = 0;
    while ($offset < length($buf)) {
        my $written = syswrite($client, $buf, length($buf) - $offset, $offset);
        last if !defined $written || $written == 0;
        $offset += $written;
    }
}
