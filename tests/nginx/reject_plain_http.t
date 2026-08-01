#!/usr/bin/perl

use warnings;
use strict;

use IO::Socket::INET;
use IO::Socket::SSL;
use Test::More;

BEGIN {
    if (defined $ENV{TEST_NGINX_LIB}) {
        unshift @INC, $ENV{TEST_NGINX_LIB};
    }
}

use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream ssl/)
    ->has_daemon('openssl')->plan(20)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8443 ssl;

        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        anytls on;
        anytls_password test-password;
        anytls_reject_plain_http on;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }

    server {
        listen 127.0.0.1:8444 ssl;

        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        anytls on;
        anytls_password test-password;
        anytls_reject_plain_http off;
        anytls_fallback 127.0.0.1:1;
        anytls_fallback_proxy_protocol on;
    }

    server {
        listen 127.0.0.1:8446 ssl;

        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        # anytls disabled: reject_plain_http must not take effect
        anytls off;
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
    . "-config $d/openssl.conf -subj /CN=localhost/ "
    . "-out $d/localhost.crt -keyout $d/localhost.key "
    . ">>$d/openssl.out 2>&1") == 0
    or die "Can't create certificate: $!\n";

$t->run();

my $p = port(8443);

# 1. plaintext HTTP GET answered with 400 page
my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s->print("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
my $resp = '';
while (my $chunk = $s->getline()) {
    $resp .= $chunk;
}
$s->close();

like($resp, qr/HTTP\/1\.1 400 Bad Request/,
    'plain HTTP request answered with 400');
like($resp, qr/plain HTTP request was sent to HTTPS port/,
    '400 page body present');
like($resp, qr/Content-Type: text\/html\r?\n/,
    'content type matches genuine nginx (no charset)');
like($resp, qr/Content-Length: 248\r?\n/,
    'content length matches genuine nginx 497 page');
like($resp, qr/<hr><center>nginx<\/center>/,
    'nginx signature line present in page body');

# 2. long request line still answered with 400 (no peek starvation)
my $s2 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s2->print("GET /some/path/" . ('x' x 100) . " HTTP/1.1\r\nHost: x\r\n\r\n");
my $resp2 = '';
while (my $chunk = $s2->getline()) {
    $resp2 .= $chunk;
    last if $chunk =~ /^\r?$/;
}
$s2->close();

like($resp2, qr/HTTP\/1\.1 400 Bad Request/,
    'long request line still answered with 400');

# 3. request line and headers sent in multiple segments still get 497
my $s3 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s3->print("GET / HTTP/1.1\r\n");
select undef, undef, undef, 0.05;
$s3->print("Host: x\r\n\r\n");
my $resp3 = '';
while (my $chunk = $s3->getline()) {
    $resp3 .= $chunk;
}
$s3->close();

like($resp3, qr/plain HTTP request was sent to HTTPS port/,
    'split request line/headers still get the 497 page');

# 4. method token split across segments still gets 497
my $s4 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s4->print("GE");
select undef, undef, undef, 0.05;
$s4->print("T / HTTP/1.1\r\nHost: x\r\n\r\n");
my $resp4 = '';
while (my $chunk = $s4->getline()) {
    $resp4 .= $chunk;
}
$s4->close();

like($resp4, qr/plain HTTP request was sent to HTTPS port/,
    'method split across segments still gets the 497 page');

# 5. long request line within the peek budget still gets 497
my $s5 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s5->print("GET /" . ('a' x 1100) . " HTTP/1.1\r\nHost: x\r\n\r\n");
my $resp5 = '';
while (my $chunk = $s5->getline()) {
    $resp5 .= $chunk;
}
$s5->close();

like($resp5, qr/plain HTTP request was sent to HTTPS port/,
    'long request line within peek budget gets the 497 page');

# 5b. request line beyond the peek budget gets default 400
my $s5b = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 5);
$s5b->print("GET /" . ('a' x 40000) . " HTTP/1.1\r\nHost: x\r\n\r\n");
my $resp5b = '';
while (my $chunk = $s5b->getline()) {
    $resp5b .= $chunk;
}
$s5b->close();

like($resp5b, qr/HTTP\/1\.1 400 Bad Request/,
    'request line beyond peek budget answered with default 400');
unlike($resp5b, qr/plain HTTP request was sent/,
    'request line beyond peek budget does not get the 497 page');

# 6. CONNECT method answered with 405 Not Allowed
my $s6 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s6->print("CONNECT host:443 HTTP/1.1\r\nHost: x\r\n\r\n");
my $resp6 = '';
while (my $chunk = $s6->getline()) {
    $resp6 .= $chunk;
}
$s6->close();

like($resp6, qr/HTTP\/1\.1 405 Not Allowed/,
    'CONNECT answered with 405 Not Allowed');
like($resp6, qr/<title>405 Not Allowed<\/title>/,
    '405 page body present');

# 7. TRACE also answered with 405 Not Allowed
my $s7 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s7->print("TRACE / HTTP/1.1\r\nHost: x\r\n\r\n");
my $resp7 = '';
while (my $chunk = $s7->getline()) {
    $resp7 .= $chunk;
}
$s7->close();

like($resp7, qr/HTTP\/1\.1 405 Not Allowed/,
    'TRACE answered with 405 Not Allowed');

# 8. CONNECT HTTP/1.1 without Host gets 400, not 405 (Host first)
my $s8 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s8->print("CONNECT x:443 HTTP/1.1\r\n\r\n");
my $resp8 = '';
while (my $chunk = $s8->getline()) {
    $resp8 .= $chunk;
}
$s8->close();

like($resp8, qr/HTTP\/1\.1 400 Bad Request/,
    'CONNECT HTTP/1.1 without Host answered with 400');

# 9. non-HTTP plaintext (SMTP-style) answered with default 400 page
my $s9 = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . $p, Timeout => 3);
$s9->print("HELO example.com\r\n");
my $resp9 = '';
while (my $chunk = $s9->getline()) {
    $resp9 .= $chunk;
}
$s9->close();

like($resp9, qr/HTTP\/1\.1 400 Bad Request/,
    'non-HTTP plaintext answered with default 400');
unlike($resp9, qr/plain HTTP request was sent/,
    'non-HTTP plaintext does not get the 497 page');

# 4. TLS handshake unaffected on the same port
my $ssl = IO::Socket::SSL->new(
    PeerAddr        => '127.0.0.1:' . $p,
    SSL_verify_mode => SSL_VERIFY_NONE,
    SSL_version     => 'TLSv12',
    Timeout         => 5,
);
ok($ssl, 'TLS handshake succeeds on same port');
$ssl->close() if $ssl;

# 6. anytls off: reject_plain_http does not apply (plaintext not answered)
my $s_off2 = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . port(8446), Timeout => 3);
$s_off2->print("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
my $resp_off2 = '';
my $n_off2 = sysread($s_off2, $resp_off2, 100);
$s_off2->close();

ok(!defined($n_off2) || $n_off2 == 0 || $resp_off2 !~ /400 Bad Request/,
    'anytls off: plaintext not answered with 400');

# 7. explicitly off: plaintext is not answered with 400
my $s_off = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . port(8444), Timeout => 3);
$s_off->print("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
my $resp_off = '';
my $n_off = sysread($s_off, $resp_off, 100);
$s_off->close();

ok(!defined($n_off) || $n_off == 0 || $resp_off !~ /400 Bad Request/,
    'explicitly off: plaintext not answered with 400');
