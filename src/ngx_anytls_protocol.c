#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/sha.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/md5.h>
#pragma GCC diagnostic pop

#include "ngx_anytls_protocol.h"

static uint16_t
ngx_anytls_get_be16(u_char *p)
{
    return (uint16_t) ((p[0] << 8) | p[1]);
}

static uint32_t
ngx_anytls_get_be32(u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

void
ngx_anytls_sha256(ngx_str_t *password, u_char out[32])
{
    SHA256(password->data, password->len, out);
}

void
ngx_anytls_md5_hex(u_char *data, size_t len, u_char out[33])
{
    u_char md5[16];
    static u_char hex[] = "0123456789abcdef";
    ngx_uint_t i;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    MD5(data, len, md5);
#pragma GCC diagnostic pop

    for (i = 0; i < 16; i++) {
        out[i * 2] = hex[md5[i] >> 4];
        out[i * 2 + 1] = hex[md5[i] & 0x0f];
    }

    out[32] = '\0';
}

ngx_int_t
ngx_anytls_parse_frame(u_char *pos, u_char *last, ngx_anytls_frame_t *frame,
    size_t *consumed)
{
    size_t avail;

    avail = (size_t) (last - pos);
    if (avail < NGX_ANYTLS_FRAME_HEADER_LEN) {
        return NGX_AGAIN;
    }

    frame->cmd = pos[0];
    frame->stream_id = ngx_anytls_get_be32(pos + 1);
    frame->data_len = ngx_anytls_get_be16(pos + 5);

    if (avail < (size_t) NGX_ANYTLS_FRAME_HEADER_LEN + frame->data_len) {
        return NGX_AGAIN;
    }

    frame->data = frame->data_len ? pos + NGX_ANYTLS_FRAME_HEADER_LEN : NULL;
    *consumed = NGX_ANYTLS_FRAME_HEADER_LEN + frame->data_len;

    if (frame->cmd > NGX_ANYTLS_CMD_SERVER_SETTINGS) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

u_char *
ngx_anytls_write_frame_header(u_char *p, ngx_uint_t cmd, uint32_t stream_id,
    uint16_t len)
{
    *p++ = (u_char) cmd;
    *p++ = (u_char) (stream_id >> 24);
    *p++ = (u_char) (stream_id >> 16);
    *p++ = (u_char) (stream_id >> 8);
    *p++ = (u_char) stream_id;
    *p++ = (u_char) (len >> 8);
    *p++ = (u_char) len;
    return p;
}

ngx_int_t
ngx_anytls_parse_settings(ngx_pool_t *pool, u_char *data, size_t len,
    ngx_anytls_settings_t *settings)
{
    u_char *p, *last, *line, *eq;
    size_t  n;

    ngx_memzero(settings, sizeof(*settings));
    settings->version = 1;

    p = data;
    last = data + len;

    while (p < last) {
        line = p;
        while (p < last && *p != '\n' && *p != '\r') {
            p++;
        }

        n = (size_t) (p - line);
        while (p < last && (*p == '\n' || *p == '\r')) {
            p++;
        }

        if (n == 0) {
            continue;
        }

        eq = ngx_strlchr(line, line + n, '=');
        if (eq == NULL) {
            continue;
        }

        if ((size_t) (eq - line) == 1 && line[0] == 'v') {
            settings->version = ngx_atoi(eq + 1, n - 2);
            if (settings->version == (ngx_uint_t) NGX_ERROR) {
                settings->version = 1;
            }
            continue;
        }

        if ((size_t) (eq - line) == sizeof("client") - 1
            && ngx_strncmp(line, "client", sizeof("client") - 1) == 0)
        {
            settings->client.len = n - (size_t) (eq - line) - 1;
            settings->client.data = ngx_pnalloc(pool, settings->client.len);
            if (settings->client.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(settings->client.data, eq + 1, settings->client.len);
            continue;
        }

        if ((size_t) (eq - line) == sizeof("padding-md5") - 1
            && ngx_strncmp(line, "padding-md5", sizeof("padding-md5") - 1) == 0)
        {
            settings->padding_md5.len = n - (size_t) (eq - line) - 1;
            settings->padding_md5.data = ngx_pnalloc(pool,
                                                     settings->padding_md5.len);
            if (settings->padding_md5.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(settings->padding_md5.data, eq + 1,
                       settings->padding_md5.len);
        }
    }

    return NGX_OK;
}

const char *
ngx_anytls_cmd_name(ngx_uint_t cmd)
{
    static const char *names[] = {
        "WASTE", "SYN", "PSH", "FIN", "SETTINGS", "ALERT",
        "UPDATE_PADDING", "SYNACK", "HEART_REQUEST", "HEART_RESPONSE",
        "SERVER_SETTINGS"
    };

    if (cmd > NGX_ANYTLS_CMD_SERVER_SETTINGS) {
        return "UNKNOWN";
    }

    return names[cmd];
}
