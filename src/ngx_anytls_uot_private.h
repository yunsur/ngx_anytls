#ifndef NGX_ANYTLS_UOT_PRIVATE_H_INCLUDED
#define NGX_ANYTLS_UOT_PRIVATE_H_INCLUDED

/* UoT private types — pending packet queue.
 * Included from connection_private.h for backward compat. */

#include <ngx_config.h>
#include <ngx_core.h>

/* Pending struct — generic stream pending queue */
struct ngx_anytls_pending_s {
    ngx_anytls_pending_t    *next;
    u_char                  *data;
    size_t                   len;
    size_t                   sent;
};

/* UoT pending packet entry */
typedef struct {
    ngx_queue_t              queue;
    u_char                  *domain;
    size_t                   domain_len;
    uint16_t                 port;
    u_char                  *payload;
    size_t                   payload_len;
} ngx_anytls_uot_pending_t;

#endif
