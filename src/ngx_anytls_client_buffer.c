#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_anytls_client_buffer.h"


static ngx_int_t
ngx_anytls_client_buffer_resize(ngx_anytls_client_buffer_t *buffer,
    size_t capacity, ngx_log_t *log)
{
    u_char *data;

    data = ngx_alloc(capacity, log);
    if (data == NULL) {
        return NGX_ERROR;
    }

    if (buffer->remnant_len != 0) {
        ngx_memcpy(data, buffer->data, buffer->remnant_len);
    }
    if (buffer->data != NULL) {
        ngx_free(buffer->data);
    }

    buffer->data = data;
    buffer->capacity = capacity;

    return NGX_OK;
}


void
ngx_anytls_client_buffer_init(ngx_anytls_client_buffer_t *buffer)
{
    buffer->data = NULL;
    buffer->capacity = 0;
    buffer->remnant_len = 0;
}


ngx_int_t
ngx_anytls_client_buffer_prepare(ngx_anytls_client_buffer_t *buffer,
    ngx_uint_t authenticated, ngx_log_t *log)
{
    size_t required;

    if (buffer->remnant_len > buffer->capacity) {
        return NGX_ERROR;
    }

    if (buffer->data == NULL) {
        if (buffer->remnant_len != 0) {
            return NGX_ERROR;
        }
        if (ngx_anytls_client_buffer_resize(
                buffer, NGX_ANYTLS_CLIENT_BUFFER_INITIAL_SIZE, log) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (!authenticated || buffer->remnant_len < NGX_ANYTLS_FRAME_HEADER_LEN) {
        return NGX_OK;
    }

    required = NGX_ANYTLS_FRAME_HEADER_LEN
               + ((size_t) buffer->data[5] << 8) + buffer->data[6];
    if (required <= buffer->capacity) {
        return NGX_OK;
    }
    if (required > NGX_ANYTLS_CLIENT_BUFFER_MAX_SIZE) {
        return NGX_ERROR;
    }

    return ngx_anytls_client_buffer_resize(buffer, required, log);
}


void
ngx_anytls_client_buffer_release_if_idle(
    ngx_anytls_client_buffer_t *buffer, ngx_uint_t active_streams)
{
    if (active_streams != 0 || buffer->remnant_len != 0) {
        return;
    }

    if (buffer->data != NULL) {
        ngx_free(buffer->data);
    }
    buffer->data = NULL;
    buffer->capacity = 0;
}


void
ngx_anytls_client_buffer_destroy(ngx_anytls_client_buffer_t *buffer)
{
    if (buffer->data != NULL) {
        ngx_free(buffer->data);
    }

    buffer->data = NULL;
    buffer->capacity = 0;
    buffer->remnant_len = 0;
}
