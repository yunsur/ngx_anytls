#ifndef NGX_ANYTLS_CLIENT_MUX_PRIVATE_H_INCLUDED
#define NGX_ANYTLS_CLIENT_MUX_PRIVATE_H_INCLUDED

/* Client mux private types — out_frame struct and free-frame pool.
 * Included from connection_private.h for backward compat. */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_client_mux.h"

struct ngx_anytls_out_frame_s {
    ngx_anytls_out_frame_t  *next;
    ngx_chain_t             *first;
    ngx_chain_t             *last;
    ngx_chain_t             *payload;
    ngx_anytls_stream_t     *stream;
    ngx_anytls_frame_handler_pt handler;
    size_t                   length;
    ngx_uint_t               cmd;
    ngx_chain_t              header_chain;
    ngx_buf_t                header_buf;
    u_char                   header[NGX_ANYTLS_FRAME_HEADER_LEN];
    ngx_chain_t              payload_chain;
    ngx_buf_t                payload_buf;
    unsigned                 blocked:1;
    unsigned                 fin:1;
    unsigned                 own_payload:1;
    unsigned                 recycle_payload:1;
};

#endif
