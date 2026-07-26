# ngx_stream_anytls_module

AnyTLS v2 inbound server for nginx stream. Implements the server side of the AnyTLS transport protocol — the same protocol used by `sing-box`/`sing-anytls` — as an nginx stream dynamic module.

## Features

- **AnyTLS v2 protocol** — full session handshake, stream multiplexing, padding, UoT (UDP over TCP)
- **Authentication failure fallback** — non-AnyTLS clients or auth failures forward to a fallback upstream with optional PROXY protocol header
- **Stream multiplexing** — multiple TCP/UDP streams multiplexed over a single TLS connection
- **UoT (UDP over TCP)** — UDP packet encapsulation over AnyTLS streams with configurable pending queue
- **Configurable padding** — built-in default padding scheme or custom padding file
- **DNS cache** — worker-local cache for domain targets; async resolver when nginx `resolver` is configured, synchronous system resolution fallback otherwise
- **Self-contained** — all protocol logic in module source; no external library dependency beyond OpenSSL

## Directives

### `anytls`

- **Syntax:** `anytls on | off;`
- **Default:** `off`
- **Context:** `stream`, `server`

Enable or disable AnyTLS processing for the server block.

### `anytls_password`

- **Syntax:** `anytls_password <string>;`
- **Default:** —
- **Context:** `stream`, `server`
- **Required:** yes (when `anytls on`)

AnyTLS password. Stored as SHA-256 hash internally.

### `anytls_padding`

- **Syntax:** `anytls_padding <path>;`
- **Default:** built-in padding scheme
- **Context:** `stream`, `server`

Path to a padding scheme file. If not specified, a built-in default is used:

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

### `anytls_fallback`

- **Syntax:** `anytls_fallback <address>;`
- **Default:** —
- **Context:** `stream`, `server`
- **Required:** yes (when `anytls on`)

Fallback upstream for connections where AnyTLS authentication fails. Plain TLS clients (e.g. web browsers, curl) hitting the AnyTLS port are also forwarded here. Set to `127.0.0.1:1` if you don't need fallback traffic.

### `anytls_fallback_proxy_protocol`

- **Syntax:** `anytls_fallback_proxy_protocol on | off;`
- **Default:** —
- **Context:** `stream`, `server`
- **Required:** yes (must be explicitly set)

When `on`, prepends a PROXY protocol v1 header on fallback connections before replaying buffered bytes.

### `anytls_buffer_size`

- **Syntax:** `anytls_buffer_size <size>;`
- **Default:** `65535`
- **Context:** `stream`, `server`

Per-stream read buffer size for upstream data. Controls how many bytes are read from the upstream connection at a time.

### `anytls_max_streams`

- **Syntax:** `anytls_max_streams <number>;`
- **Default:** `1024`
- **Context:** `stream`, `server`

Maximum concurrent multiplexed streams per AnyTLS connection.
Hash table size scales dynamically to 2x max_streams.

### `anytls_max_pending_output`

- **Syntax:** `anytls_max_pending_output <size>;`
- **Default:** `8m`
- **Context:** `stream`, `server`

Maximum pending output (frames waiting to be sent to the client) per connection. When exceeded, upstream reads are blocked until the output drains.

### `anytls_max_pending_input`

- **Syntax:** `anytls_max_pending_input <size>;`
- **Default:** `8m`
- **Context:** `stream`, `server`

Maximum pending input (data from client waiting to be forwarded upstream) per connection. When exceeded, client reads are blocked until the upstream drains the queue.

### `anytls_write_timeout`

- **Syntax:** `anytls_write_timeout <time>;`
- **Default:** `60s`
- **Context:** `stream`, `server`

Maximum time a connection may keep unsent output queued to the client before the session is closed. Set to `0` to disable this timeout.

### `anytls_uot_pending_packets`

- **Syntax:** `anytls_uot_pending_packets <number>;`
- **Default:** `256`
- **Context:** `stream`, `server`

Maximum pending UDP packets per UoT stream before applying backpressure.

### `anytls_uot_pending_bytes`

- **Syntax:** `anytls_uot_pending_bytes <size>;`
- **Default:** `512k`
- **Context:** `stream`, `server`

Maximum pending UDP data bytes per UoT stream before applying backpressure.

## Nginx standard directives used by this module

- [`resolver`](https://nginx.org/en/docs/stream/ngx_stream_core_module.html#resolver) — DNS resolver for upstream domain name resolution. Without it, the module falls back to synchronous system resolution.
- [`resolver_timeout`](https://nginx.org/en/docs/stream/ngx_stream_core_module.html#resolver_timeout) — DNS resolver timeout (default: `30s`).

## Installation

The module is self-contained — all protocol logic is implemented in the module source. It requires only OpenSSL and the standard nginx stream/ssl modules.

```bash
cd /path/to/nginx
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --add-module=/path/to/ngx_anytls
make
```

### Docker

A Dockerfile builds nginx + ngx_anytls as a `.deb` package via nginx's `pkg-oss` system:

```bash
docker build \
    --build-arg NGINX_VERSION=1.28.0 \
    -t ngx-anytls-builder \
    -f ngx_anytls/docker/Dockerfile \
    ngx_anytls
```

## Example

```nginx
stream {
    resolver 1.1.1.1 8.8.8.8 valid=60s;
    resolver_timeout 5s;

    server {
        listen 443 ssl;

        ssl_certificate     /path/to/fullchain.pem;
        ssl_certificate_key /path/to/privkey.pem;

        anytls on;
        anytls_password your-password;

        anytls_fallback 127.0.0.1:8080;
        anytls_fallback_proxy_protocol on;

        anytls_buffer_size 65535;
        anytls_max_pending_output 8m;
        anytls_max_pending_input 8m;
        anytls_write_timeout 60s;
    }
}
```

## DNS Cache Notes

AnyTLS TCP and UoT domain targets share a worker-local DNS cache. Cache entries expire based on their TTL. Cache misses use the nginx async `resolver` when configured; without one, the module falls back to synchronous system resolution (getaddrinfo).

## Testing

Integration tests use the upstream nginx Perl test harness.

1. Build nginx with stream SSL and this module
2. Clone nginx-tests:
   ```bash
   git clone https://github.com/nginx/nginx-tests.git /path/to/nginx-tests
   ```
3. Run tests:
   ```bash
   TEST_NGINX_BINARY=/path/to/nginx/objs/nginx \
   TEST_NGINX_LIB=/path/to/nginx-tests/lib \
   make test-nginx
   ```

`TEST_NGINX_LIB` defaults to `../nginx-tests/lib` when nginx-tests is checked out next to this repository.

## Protocol Reference

See [`docs/protocol.md`](./docs/protocol.md) for the AnyTLS v2 protocol specification.

## Logging Notes

- `status=200` (`NGX_STREAM_OK`) means the stream session ended normally. Control-only sessions (no business stream) also report `200` with empty `$upstream_addr`.
- `$upstream_addr` is populated when an upstream state entry is opened — normal AnyTLS TCP/UoT paths record it on stream open; auth-failed fallback also records it.
- Session teardown logs include upstream buffer budget diagnostics.
