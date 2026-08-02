#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_anytls_padding.h"
#include "ngx_anytls_protocol.h"
#include "ngx_anytls_connection_private.h"

ngx_int_t
ngx_anytls_padding_validate(u_char *data, size_t len)
{
    u_char *p, *last, *eq;
    ngx_uint_t saw_stop = 0;

    if (data == NULL || len == 0) {
        return NGX_ERROR;
    }

    p = data;
    last = data + len;

    while (p < last) {
        while (p < last && (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')) {
            p++;
        }
        if (p == last) {
            break;
        }
        if (*p == '#') {
            while (p < last && *p != '\n') {
                p++;
            }
            continue;
        }
        eq = p;
        while (eq < last && *eq != '=' && *eq != '\n' && *eq != '\r') {
            eq++;
        }
        if (eq == last || *eq != '=') {
            return NGX_ERROR;
        }
        if ((size_t) (eq - p) == sizeof("stop") - 1
            && ngx_strncmp(p, "stop", sizeof("stop") - 1) == 0)
        {
            saw_stop = 1;
        }
        p = eq + 1;
        while (p < last && *p != '\n' && *p != '\r') {
            p++;
        }
    }

    return saw_stop ? NGX_OK : NGX_ERROR;
}

char *
ngx_anytls_padding_load(ngx_conf_t *cf, ngx_stream_anytls_srv_conf_t *conf)
{
    ngx_file_t       f;
    ngx_file_info_t  fi;
    off_t            fsize;

    if (conf->padding_data != NULL) {
        return NGX_CONF_OK;
    }

    if (conf->padding_file.data == NULL) {
        conf->padding_data_len = sizeof(NGX_ANYTLS_DEFAULT_PADDING) - 1;
        conf->padding_data = ngx_pnalloc(cf->pool, conf->padding_data_len);
        if (conf->padding_data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(conf->padding_data, NGX_ANYTLS_DEFAULT_PADDING,
                   conf->padding_data_len);
        ngx_anytls_md5_hex(conf->padding_data, conf->padding_data_len,
                           conf->padding_md5);
        return NGX_CONF_OK;
    }

    ngx_memzero(&f, sizeof(f));
    f.name = conf->padding_file;
    f.log = cf->log;

    f.fd = ngx_open_file(conf->padding_file.data, NGX_FILE_RDONLY,
                         NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
    if (f.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "anytls: " ngx_open_file_n " \"%s\" failed",
                           conf->padding_file.data);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(f.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "anytls: ngx_fd_info \"%s\" failed",
                           conf->padding_file.data);
        ngx_close_file(f.fd);
        return NGX_CONF_ERROR;
    }

    fsize = ngx_file_size(&fi);
    /* the scheme is sent to clients as a CMD_UPDATE_PADDING frame, whose
     * length field is uint16: a larger file would overflow the frame and
     * break every session */
    if (fsize <= 0 || fsize > NGX_ANYTLS_MAX_FRAME_DATA) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "anytls: padding file \"%s\" size %O is invalid",
                           conf->padding_file.data, fsize);
        ngx_close_file(f.fd);
        return NGX_CONF_ERROR;
    }

    conf->padding_data = ngx_palloc(cf->pool, (size_t) fsize);
    if (conf->padding_data == NULL) {
        ngx_close_file(f.fd);
        return NGX_CONF_ERROR;
    }

    if (ngx_read_file(&f, conf->padding_data, (size_t) fsize, 0) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "anytls: read \"%s\" failed",
                           conf->padding_file.data);
        ngx_close_file(f.fd);
        return NGX_CONF_ERROR;
    }
    ngx_close_file(f.fd);

    conf->padding_data_len = (size_t) fsize;
    if (ngx_anytls_padding_validate(conf->padding_data, conf->padding_data_len)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "anytls: padding file \"%s\" has invalid format",
                           conf->padding_file.data);
        return NGX_CONF_ERROR;
    }

    ngx_anytls_md5_hex(conf->padding_data, conf->padding_data_len,
                       conf->padding_md5);

    return NGX_CONF_OK;
}
