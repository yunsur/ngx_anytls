#!/usr/bin/perl

use warnings;
use strict;

use Test::More;
use File::Temp qw/ tempdir /;

# binary selection only; no Test::Nginx object is constructed (its
# destructor expects a run() and would warn during global destruction)
BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

# Pure `nginx -t` config validation: no server is started.

my $nginx = $Test::Nginx::NGINX;
BAIL_OUT("no $nginx binary found") unless -x $nginx;
my $testdir = tempdir(CLEANUP => 1);

plan(tests => 3);

# runs `nginx -t` against a config in the temp dir and checks the
# expected config-time error appears on stderr
sub config_fails_with {
    my ($name, $users, $pattern) = @_;

    open my $fh, '>', "$testdir/$name" or die "open $name: $!";
    print $fh <<"EOF";
error_log $testdir/$name.log;
events {
}
stream {
    server {
        listen 127.0.0.1:8080;

        anytls on;
$users
        anytls_fallback 127.0.0.1:1;
    }
}
EOF
    close $fh;

    my $out = `$nginx -t -p $testdir/ -c $name 2>&1`;
    return $out =~ /$pattern/;
}

ok(config_fails_with('dup_name.conf',
        'anytls_user dup p1; anytls_user dup p2;',
        'duplicate user name "dup"'),
    'duplicate anytls_user name rejected at config time');

ok(config_fails_with('dup_pass.conf',
        'anytls_user a same; anytls_user b same;',
        'duplicate password for "anytls_user a" and "anytls_user b"'),
    'duplicate anytls_user password rejected at config time');

ok(config_fails_with('empty_name.conf',
        'anytls_user "" pass;',
        'name must not be empty'),
    'empty anytls_user name rejected at config time');
