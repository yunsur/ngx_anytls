#ifndef NGX_ANYTLS_REJECT_PLAIN_HTTP_H_INCLUDED
#define NGX_ANYTLS_REJECT_PLAIN_HTTP_H_INCLUDED

#include "ngx_stream_anytls_module.h"

/* Registers the preread-phase handler that replies 400 to plaintext
 * HTTP requests arriving on a TLS/AnyTLS port (anytls_reject_plain_http on).
 * Must be called from the module's postconfiguration. */
ngx_int_t ngx_anytls_reject_plain_http_postconfiguration(ngx_conf_t *cf);

#endif
