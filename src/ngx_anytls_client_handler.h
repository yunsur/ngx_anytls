#ifndef NGX_ANYTLS_CLIENT_HANDLER_H_INCLUDED
#define NGX_ANYTLS_CLIENT_HANDLER_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

struct ngx_anytls_connection_s;
typedef struct ngx_anytls_connection_s ngx_anytls_connection_t;

void ngx_anytls_client_read_handler(ngx_event_t *rev);
void ngx_anytls_client_write_handler(ngx_event_t *wev);

ngx_int_t ngx_anytls_client_input_pause(ngx_anytls_connection_t *ac);
ngx_int_t ngx_anytls_client_input_resume(ngx_anytls_connection_t *ac);

#endif
