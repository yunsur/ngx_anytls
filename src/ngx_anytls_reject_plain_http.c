#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_reject_plain_http.h"
#include "ngx_anytls_connection_private.h"


#define NGX_ANYTLS_REJECT_PLAIN_HTTP_TIMEOUT  60000
#define NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK     (4 * 8192)  /* large_client_header_buffers */

/* nginx/OpenSSL needs at least a full TLS record header plus one byte
 * before it classifies plaintext; shorter input gets no response and
 * the connection times out.  Match that so a 5-byte probe does not get
 * an immediate answer. */
#define NGX_ANYTLS_REJECT_PLAIN_HTTP_MIN_PEEK  7


static ngx_int_t
ngx_anytls_reject_plain_http_is_http(u_char *p, size_t len)
{
    /* methods observed to trigger nginx's 497 page (OpenSSL HTTP
     * detection); HEAD gets the default 400, CONNECT/TRACE get 405 */
    static const char *methods[] = {
        "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
    };

    u_char *s, *e, *last, *rl_end;
    size_t  i, mlen, n;
    ngx_uint_t  saw_host, http11, http10, not_allowed;

    /* HTTP request line start: METHOD SP URI, restricted to the known
     * HTTP methods so SMTP/FTP/IRC-style "WORD arg" plaintext (HELO,
     * USER, PASS, ...) is not misanswered with a 400 page. */
    if (len < NGX_ANYTLS_REJECT_PLAIN_HTTP_MIN_PEEK) {
        return NGX_AGAIN;   /* too short: nginx answers nothing */
    }

    s = p;
    last = p + len;

    while (s < last && *s != ' ') {
        if (*s < 'A' || *s > 'Z') {
            /* '-', CR, LF, ... inside the method token: not an HTTP
             * request (SSH banners, bare "GET\r\n", etc.) */
            return NGX_ERROR;
        }
        s++;
    }

    if (s == last) {
        return NGX_AGAIN;      /* method not complete yet */
    }

    mlen = (size_t) (s - p);

    if (mlen > 12) {
        return NGX_ERROR;      /* method token too long */
    }

    not_allowed = 0;

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        n = ngx_strlen((u_char *) methods[i]);

        if (mlen == n && ngx_strncmp(p, (u_char *) methods[i], n) == 0) {
            if (s + 1 >= last) {
                return NGX_AGAIN;      /* need at least one URI byte */
            }

            if (s[1] == ' ' || s[1] == '\r' || s[1] == '\n') {
                return NGX_ERROR;      /* empty URI */
            }

            break;
        }
    }

    if (i == sizeof(methods) / sizeof(methods[0])) {
        /* CONNECT/TRACE are real HTTP methods but not allowed on origin
         * servers: nginx answers 405 (after the Host check), which we
         * signal via NGX_BUSY */
        if ((mlen == sizeof("CONNECT") - 1
             && ngx_strncmp(p, (u_char *) "CONNECT", sizeof("CONNECT") - 1) == 0)
            || (mlen == sizeof("TRACE") - 1
                && ngx_strncmp(p, (u_char *) "TRACE", sizeof("TRACE") - 1) == 0))
        {
            not_allowed = 1;
        } else {
            return NGX_ERROR;      /* unknown method token */
        }
    }

    /* nginx emits the 497 page only when the request parses fully,
     * which for HTTP/1.1 requires a valid Host header; without one it
     * answers the default 400 instead.  A request line that never
     * completes (no CRLF yet) gets the default 400 immediately; a
     * completed request line waits for the full headers. */

    /* end of request line: first CRLF after the method */
    ngx_uint_t  found_req_end = 0;

    for (e = s + 1; e + 1 < last; e++) {
        if (e[0] == '\r' && e[1] == '\n') {
            e += 2;
            found_req_end = 1;
            break;
        }

        if (e[0] == '\n') {
            e += 1;
            found_req_end = 1;
            break;
        }
    }

    if (!found_req_end) {
        /* data ran out inside the request line.  Wait for more unless
         * the line is already invalid (space in the URI where the
         * version should start, control chars, or a version part that
         * is not HTTP/...). */
        u_char *q, *v;
        size_t  vlen, match;

        for (q = s + 1; q < last; q++) {
            if (*q == ' ') {
                v = q + 1;
                vlen = (size_t) (last - v);

                if (vlen == 0) {
                    /* version not started: wait unless peek is full */
                    return (len >= NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK)
                           ? NGX_ERROR : NGX_AGAIN;
                }

                match = 0;
                while (match < 5 && match < vlen
                       && v[match] == (u_char) "HTTP/"[match])
                {
                    match++;
                }

                if (match == vlen && vlen < 5) {
                    /* partial "HTTP": wait unless peek is full */
                    return (len >= NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK)
                           ? NGX_ERROR : NGX_AGAIN;
                }

                if (match == 5) {
                    /* version incomplete: wait unless peek is full */
                    return (len >= NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK)
                           ? NGX_ERROR : NGX_AGAIN;
                }

                return NGX_ERROR;          /* not HTTP/: invalid line */
            }

            if (*q <= 0x1F || *q == 0x7F) {
                return NGX_ERROR;          /* control char in URI */
            }
        }

        /* URI only, no version yet: wait unless the peek buffer is full
         * (peek does not consume, so state cannot advance) */
        return (len >= NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK)
               ? NGX_ERROR : NGX_AGAIN;
    }

    /* HTTP version in the request line: nginx only requires Host for
     * HTTP/1.1; HTTP/1.0 gets the 497 page without one */
    rl_end = e;
    http11 = 0;
    http10 = 0;

    for (s = p; s + 7 < rl_end; s++) {
        if (ngx_strncmp(s, "HTTP/1.1", 8) == 0) {
            http11 = 1;
        }
        if (ngx_strncmp(s, "HTTP/1.0", 8) == 0) {
            http10 = 1;
        }
    }

    s = rl_end;

    if (s >= last) {
        /* request line complete, waiting for headers; versions other
         * than 1.0/1.1 (0.9 etc.) have no headers and get the default
         * 400 right away */
        if (!http11 && !http10) {
            return NGX_ERROR;
        }

        /* waiting for headers: bail out if the peek buffer is full */
        return (len >= NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK)
               ? NGX_ERROR : NGX_AGAIN;
    }

    /* scan header lines for Host and for the empty line that ends the
     * headers (CRLF CRLF) */
    saw_host = 0;

    for ( ;; ) {
        u_char  *line_start = s;

        while (s + 1 < last && !(s[0] == '\r' && s[1] == '\n')) {
            s++;
        }

        if (s + 1 >= last) {
            /* header line incomplete: wait unless peek is full */
            return (len >= NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK)
                   ? NGX_ERROR : NGX_AGAIN;
        }

        /* Host: check, case-insensitive */
        if (s - line_start > 4
            && (line_start[0] == 'H' || line_start[0] == 'h')
            && (line_start[1] == 'O' || line_start[1] == 'o')
            && (line_start[2] == 'S' || line_start[2] == 's')
            && (line_start[3] == 'T' || line_start[3] == 't')
            && line_start[4] == ':')
        {
            saw_host = 1;
        }

        if (s == line_start) {
            /* empty line: end of headers.  Host is checked first (an
             * HTTP/1.1 request without Host gets 400 even for
             * CONNECT/TRACE); then CONNECT/TRACE get 405, the rest get
             * 497 when the request is otherwise valid */
            if (not_allowed) {
                return ((http11 && saw_host) || http10)
                       ? NGX_BUSY : NGX_ERROR;
            }

            return ((http11 && saw_host) || http10) ? NGX_OK : NGX_ERROR;
        }

        s += 2;      /* skip CRLF */
    }
}


static void
ngx_anytls_reject_plain_http_send_page(ngx_stream_session_t *s,
    ngx_connection_t *c, u_char *status, u_char *body, size_t body_len)
{
    u_char  buf[512];
    u_char *p;
    size_t  len;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "anytls: rejecting plaintext request on TLS port");

    p = ngx_sprintf(buf,
        "HTTP/1.1 %s" CRLF
        "Server: nginx" CRLF
        "Date: %V" CRLF
        "Content-Type: text/html" CRLF
        "Content-Length: %uz" CRLF
        "Connection: close" CRLF
        CRLF,
        status,
        &ngx_cached_http_time,
        body_len);

    len = (size_t) (p - buf);
    ngx_memcpy(p, body, body_len);
    len += body_len;

    (void) c->send(c, buf, len);

    /* the plaintext was peeked, not consumed: drain it via the raw
     * descriptor so the close is a FIN rather than an RST (nginx
     * consumes the data it read; c->recv may already be the ssl
     * variant, which cannot read before the handshake) */
    {
        ssize_t  drained = 0;

        for ( ;; ) {
            ssize_t  d;

            d = recv(c->fd, buf, sizeof(buf), 0);
            if (d <= 0) {
                break;
            }
            drained += d;
        }
    }

    ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
}


static ngx_int_t
ngx_anytls_reject_plain_http_handler(ngx_stream_session_t *s)
{
    ngx_stream_anytls_srv_conf_t  *ascf;
    ngx_connection_t              *c;
    u_char                         peek[NGX_ANYTLS_REJECT_PLAIN_HTTP_PEEK];
    ssize_t                        n;
    ngx_int_t                      http;
    ngx_err_t                      err;

    ascf = ngx_stream_get_module_srv_conf(s, ngx_stream_anytls_module);
    if (!ascf->enabled || !ascf->reject_plain_http) {
        return NGX_DECLINED;
    }

    c = s->connection;

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

#if (NGX_STREAM_SSL)
    /* this handler only makes sense on TLS listeners; a non-SSL server
     * that inherited the directive must not be affected */
    if (!s->ssl) {
        return NGX_DECLINED;
    }
#endif

    if (c->read->timedout) {
        ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
        return NGX_DONE;
    }

    /*
     * Peek without consuming: the SSL handshake needs the whole
     * ClientHello intact.  This handler runs in the SSL phase before
     * ngx_stream_ssl_handler, so plaintext never reaches the TLS
     * handshake.
     */
    n = recv(c->fd, peek, sizeof(peek), MSG_PEEK);

    if (n == -1) {
        err = ngx_socket_errno;

        if (err == NGX_EAGAIN) {
            /* same as nginx's PROXY protocol peek handler: clear the
             * ready flag so ngx_handle_read_event() re-arms the read
             * event even on deferred-accept / spurious-ready paths */
            c->read->ready = 0;
            c->read->handler = ngx_stream_session_handler;
            ngx_add_timer(c->read, NGX_ANYTLS_REJECT_PLAIN_HTTP_TIMEOUT);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return NGX_DONE;
            }

            return NGX_AGAIN;
        }

        ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
        return NGX_DONE;
    }

    if (n == 0) {
        ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
        return NGX_DONE;
    }

    /* TLS ClientHello record type 0x16; SSLv2-compatible ClientHello has
     * the high bit of the first byte set. */
    if (peek[0] == 0x16 || (peek[0] & 0x80)) {
        /* drop the timer set on an earlier EAGAIN; a stale 5s timer
         * would otherwise survive into the AnyTLS session */
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        return NGX_DECLINED;
    }

    http = ngx_anytls_reject_plain_http_is_http(peek, (size_t) n);

    if (http == NGX_AGAIN) {
        /* not enough data to decide yet: wait for more */
        c->read->ready = 0;
        c->read->handler = ngx_stream_session_handler;
        ngx_add_timer(c->read, NGX_ANYTLS_REJECT_PLAIN_HTTP_TIMEOUT);

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return NGX_DONE;
        }

        return NGX_AGAIN;
    }

    if (http == NGX_OK) {
        /* byte-for-byte the http module's 497 error page (server_tokens
         * off): <title> wording, the nginx signature line and CRLF line
         * endings all matter for fingerprint parity */
        static u_char plain_http_400_body[] =
            "<html>" CRLF
            "<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>" CRLF
            "<body>" CRLF
            "<center><h1>400 Bad Request</h1></center>" CRLF
            "<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
            "<hr><center>nginx</center>" CRLF
            "</body>" CRLF
            "</html>" CRLF;

        ngx_anytls_reject_plain_http_send_page(s, c, (u_char *) "400 Bad Request",
            plain_http_400_body, sizeof(plain_http_400_body) - 1);
        return NGX_DONE;
    }

    if (http == NGX_BUSY) {
        /* CONNECT is not allowed on an origin server: nginx answers 405 */
        static u_char not_allowed_body[] =
            "<html>" CRLF
            "<head><title>405 Not Allowed</title></head>" CRLF
            "<body>" CRLF
            "<center><h1>405 Not Allowed</h1></center>" CRLF
            "<hr><center>nginx</center>" CRLF
            "</body>" CRLF
            "</html>" CRLF;

        ngx_anytls_reject_plain_http_send_page(s, c, (u_char *) "405 Not Allowed",
            not_allowed_body, sizeof(not_allowed_body) - 1);
        return NGX_DONE;
    }

    {
        /* default 400 error page for all other plaintext */
        static u_char default_400_body[] =
            "<html>" CRLF
            "<head><title>400 Bad Request</title></head>" CRLF
            "<body>" CRLF
            "<center><h1>400 Bad Request</h1></center>" CRLF
            "<hr><center>nginx</center>" CRLF
            "</body>" CRLF
            "</html>" CRLF;

        ngx_anytls_reject_plain_http_send_page(s, c, (u_char *) "400 Bad Request",
            default_400_body, sizeof(default_400_body) - 1);
        return NGX_DONE;
    }
}


ngx_int_t
ngx_anytls_reject_plain_http_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    /*
     * Register in the SSL phase, AFTER the built-in ssl module (module
     * registration order).  The phase engine walks handlers in reverse,
     * so this handler runs before ngx_stream_ssl_handler and can reject
     * plaintext before the TLS handshake starts.
     */
    h = ngx_array_push(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_anytls_reject_plain_http_handler;

    return NGX_OK;
}
