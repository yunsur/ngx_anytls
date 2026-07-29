#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_client_mux.h"
#include "ngx_anytls_output.h"
#include "ngx_anytls_stream.h"
#include "ngx_anytls_upstream_mux.h"
#include "ngx_anytls_private.h"


/* Client mux — unified output scheduling and backpressure.
 *
 * The implementation lives in ngx_anytls_output.c (and related files).
 * This file provides the canonical client_mux API by delegating to
 * the existing output-layer functions.
 */


ngx_int_t
ngx_anytls_client_mux_queue_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len)
{
    return ngx_anytls_queue_frame(ac, st, cmd, stream_id, data, len);
}


ngx_int_t
ngx_anytls_client_mux_queue_ref_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    u_char *data, size_t len)
{
    return ngx_anytls_queue_ref_frame(ac, st, cmd, stream_id, data, len);
}


ngx_int_t
ngx_anytls_client_mux_queue_chain_frame(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, ngx_uint_t cmd, uint32_t stream_id,
    ngx_chain_t *payload, size_t len, ngx_uint_t recycle_payload)
{
    return ngx_anytls_queue_chain_frame(ac, st, cmd, stream_id, payload,
                                        len, recycle_payload);
}


ngx_int_t
ngx_anytls_client_mux_send_synack(ngx_anytls_stream_t *st, u_char *data,
    size_t len)
{
    return ngx_anytls_send_synack(st, data, len);
}


ngx_int_t
ngx_anytls_client_mux_drain(ngx_anytls_connection_t *ac, ngx_uint_t budget,
    ngx_anytls_drain_result_t *result)
{
    return ngx_anytls_mux_drain_client(ac, budget, result);
}


void
ngx_anytls_client_mux_post_write(ngx_anytls_connection_t *ac)
{
    ngx_anytls_post_write(ac);
}


ngx_uint_t
ngx_anytls_client_mux_has_room(ngx_anytls_connection_t *ac, size_t len)
{
    return ngx_anytls_output_has_room(ac, len);
}


void
ngx_anytls_client_mux_on_writable(ngx_anytls_connection_t *ac)
{
    ngx_anytls_mux_on_client_writable(ac);
}


void
ngx_anytls_client_mux_resume_upstream_reads(ngx_anytls_connection_t *ac)
{
    ngx_anytls_resume_upstream_reads(ac);
}


ngx_int_t
ngx_anytls_client_mux_queue_error(ngx_anytls_connection_t *ac,
    ngx_anytls_stream_t *st, u_char *data, size_t len)
{
    return ngx_anytls_queue_ref_frame(ac, st, NGX_ANYTLS_CMD_ALERT,
                                      st ? st->id : 0, data, len);
}


void
ngx_anytls_client_mux_mark_ready(ngx_anytls_stream_t *st)
{
    if (st->queued) {
        return;
    }

    if (ngx_anytls_upstream_mux_is_uot(st)) {
        ngx_queue_insert_head(&st->ac->ready_streams, &st->ready_queue);
    } else {
        ngx_queue_insert_tail(&st->ac->ready_streams, &st->ready_queue);
    }
    st->queued = 1;
}
