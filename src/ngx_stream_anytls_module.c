#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <openssl/sha.h>

#include "ngx_stream_anytls_module.h"
#include "ngx_anytls_padding.h"
#include "ngx_anytls_reject_plain_http.h"
#include "ngx_anytls_connection.h"
#include "ngx_anytls_connection_private.h"

static void *ngx_stream_anytls_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_anytls_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_anytls_flag(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_anytls_password(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_anytls_padding(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_anytls_fallback(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_anytls_fallback_proxy_protocol(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_anytls_postconfiguration(ngx_conf_t *cf);
static char *ngx_stream_anytls_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_anytls_num_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_stream_anytls_handler(ngx_stream_session_t *s);

static ngx_command_t ngx_stream_anytls_commands[] = {

    { ngx_string("anytls"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_anytls_flag,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, enabled),
      NULL },

    { ngx_string("anytls_reject_plain_http"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_anytls_flag,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, reject_plain_http),
      NULL },

    { ngx_string("anytls_password"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_password,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("anytls_padding"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_padding,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("anytls_fallback"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_fallback,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("anytls_fallback_proxy_protocol"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_anytls_fallback_proxy_protocol,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("anytls_fallback_connect_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, fallback_connect_timeout),
      NULL },

    { ngx_string("anytls_upstream_connect_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, upstream_connect_timeout),
      NULL },

    { ngx_string("anytls_handshake_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, handshake_timeout),
      NULL },

    { ngx_string("anytls_buffer_size"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("anytls_max_streams"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, max_streams),
      NULL },

    { ngx_string("anytls_max_pending_output"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, max_pending_output),
      NULL },

    { ngx_string("anytls_max_pending_input"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, max_pending_input),
      NULL },

    { ngx_string("anytls_write_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, write_timeout),
      NULL },

    { ngx_string("anytls_uot_idle_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, uot_idle_timeout),
      NULL },

    { ngx_string("anytls_uot_pending_packets"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, uot_pending_packets),
      NULL },

    { ngx_string("anytls_uot_pending_bytes"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_anytls_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_anytls_srv_conf_t, uot_pending_bytes),
      NULL },

      ngx_null_command
};

static ngx_stream_module_t ngx_stream_anytls_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_anytls_postconfiguration,   /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    ngx_stream_anytls_create_srv_conf,     /* create server configuration */
    ngx_stream_anytls_merge_srv_conf       /* merge server configuration */
};

ngx_module_t ngx_stream_anytls_module = {
    NGX_MODULE_V1,
    &ngx_stream_anytls_module_ctx,
    ngx_stream_anytls_commands,
    NGX_STREAM_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static void *
ngx_stream_anytls_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_anytls_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_anytls_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->reject_plain_http = NGX_CONF_UNSET;
    conf->fallback_proxy_protocol = NGX_CONF_UNSET;
    conf->fallback_proxy_protocol_set = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->max_streams = NGX_CONF_UNSET_UINT;
    conf->max_pending_output = NGX_CONF_UNSET_SIZE;
    conf->max_pending_input = NGX_CONF_UNSET_SIZE;
    conf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    conf->write_timeout = NGX_CONF_UNSET_MSEC;
    conf->uot_idle_timeout = NGX_CONF_UNSET_MSEC;
    conf->fallback_connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream_connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->handshake_timeout = NGX_CONF_UNSET_MSEC;
    conf->uot_pending_packets = NGX_CONF_UNSET_UINT;
    conf->uot_pending_bytes = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_stream_anytls_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_anytls_srv_conf_t *prev = parent;
    ngx_stream_anytls_srv_conf_t *conf = child;
    ngx_stream_core_srv_conf_t   *cscf;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_value(conf->reject_plain_http, prev->reject_plain_http, 1);

    if (!conf->password_set && prev->password_set) {
        ngx_memcpy(conf->password_hash, prev->password_hash, 32);
        conf->password_set = 1;
    }

    if (conf->padding_file.data == NULL && prev->padding_file.data != NULL) {
        conf->padding_file = prev->padding_file;
        conf->padding_data = prev->padding_data;
        conf->padding_data_len = prev->padding_data_len;
        ngx_memcpy(conf->padding_md5, prev->padding_md5, 33);
    }

    if (conf->fallback == NULL && prev->fallback != NULL) {
        conf->fallback = prev->fallback;
    }

    if (conf->fallback_proxy_protocol_set == NGX_CONF_UNSET
        && prev->fallback_proxy_protocol_set != NGX_CONF_UNSET)
    {
        conf->fallback_proxy_protocol = prev->fallback_proxy_protocol;
        conf->fallback_proxy_protocol_set = prev->fallback_proxy_protocol_set;
    }
    if (conf->fallback_proxy_protocol_set == NGX_CONF_UNSET) {
        conf->fallback_proxy_protocol = 0;
        conf->fallback_proxy_protocol_set = 0;
    }

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              NGX_ANYTLS_DEFAULT_BUF_SIZE);
    ngx_conf_merge_uint_value(conf->max_streams, prev->max_streams,
                              NGX_ANYTLS_DEFAULT_MAX_STREAMS);
    if (conf->max_streams > 65536) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "anytls_max_streams %ui is too large, using 65536",
                           conf->max_streams);
        conf->max_streams = 65536;
    }

    ngx_conf_merge_size_value(conf->max_pending_output,
                              prev->max_pending_output,
                              NGX_ANYTLS_DEFAULT_MAX_PENDING);
    ngx_conf_merge_size_value(conf->max_pending_input,
                              prev->max_pending_input,
                              NGX_ANYTLS_DEFAULT_MAX_PENDING_INPUT);
    ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
                              30000);
    ngx_conf_merge_msec_value(conf->write_timeout, prev->write_timeout,
                              NGX_ANYTLS_DEFAULT_WRITE_TIMEOUT);
    ngx_conf_merge_msec_value(conf->uot_idle_timeout, prev->uot_idle_timeout,
                              NGX_ANYTLS_DEFAULT_UOT_IDLE_TIMEOUT);
    ngx_conf_merge_msec_value(conf->fallback_connect_timeout,
                              prev->fallback_connect_timeout,
                              NGX_ANYTLS_DEFAULT_FALLBACK_CONNECT_TIMEOUT);
    ngx_conf_merge_msec_value(conf->upstream_connect_timeout,
                              prev->upstream_connect_timeout,
                              NGX_ANYTLS_DEFAULT_UPSTREAM_CONNECT_TIMEOUT);
    ngx_conf_merge_msec_value(conf->handshake_timeout,
                              prev->handshake_timeout,
                              NGX_ANYTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    ngx_conf_merge_uint_value(conf->uot_pending_packets,
                              prev->uot_pending_packets,
                              NGX_ANYTLS_DEFAULT_UOT_PENDING_PACKETS);
    ngx_conf_merge_size_value(conf->uot_pending_bytes, prev->uot_pending_bytes,
                              NGX_ANYTLS_DEFAULT_UOT_PENDING_BYTES);

    if (conf->enabled) {
        if (!conf->password_set) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "anytls: \"anytls_password\" is required");
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_anytls_padding_load(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->enabled) {
        cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
        if (conf->resolver == NULL) {
            conf->resolver = prev->resolver ? prev->resolver : cscf->resolver;
        }
        if (cscf->resolver_timeout != NGX_CONF_UNSET_MSEC
            && conf->resolver_timeout == 30000)
        {
            conf->resolver_timeout = cscf->resolver_timeout;
        }
        cscf->handler = ngx_stream_anytls_handler;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_anytls_postconfiguration(ngx_conf_t *cf)
{
    return ngx_anytls_reject_plain_http_postconfiguration(cf);
}


static char *
ngx_stream_anytls_flag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return ngx_conf_set_flag_slot(cf, cmd, conf);
}

static char *
ngx_stream_anytls_password(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_anytls_srv_conf_t *ascf = conf;
    ngx_str_t *value;

    if (ascf->password_set) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ngx_anytls_sha256(&value[1], ascf->password_hash);
    ascf->password_set = 1;

    return NGX_CONF_OK;
}

static char *
ngx_stream_anytls_padding(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_anytls_srv_conf_t *ascf = conf;
    ngx_str_t *value;

    if (ascf->padding_file.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ascf->padding_file = value[1];

    return NGX_CONF_OK;
}

static char *
ngx_stream_anytls_fallback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_anytls_srv_conf_t *ascf = conf;
    ngx_str_t *value;
    ngx_stream_compile_complex_value_t ccv;

    if (ascf->fallback != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ascf->fallback = ngx_pcalloc(cf->pool, sizeof(ngx_stream_complex_value_t));
    if (ascf->fallback == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ascf->fallback;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_stream_anytls_fallback_proxy_protocol(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_anytls_srv_conf_t *ascf = conf;
    ngx_str_t *value;

    if (ascf->fallback_proxy_protocol_set != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;
    if (ngx_strcmp(value[1].data, "on") == 0) {
        ascf->fallback_proxy_protocol = 1;
    } else if (ngx_strcmp(value[1].data, "off") == 0) {
        ascf->fallback_proxy_protocol = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in "
                           "\"anytls_fallback_proxy_protocol\" directive, "
                           "it must be \"on\" or \"off\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    ascf->fallback_proxy_protocol_set = 1;
    return NGX_CONF_OK;
}

static char *
ngx_stream_anytls_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;
    ngx_str_t *value;
    ssize_t size;
    size_t *field;

    field = (size_t *) (p + cmd->offset);
    if (*field != NGX_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    value = cf->args->elts;
    size = ngx_parse_size(&value[1]);
    if (size == NGX_ERROR) {
        return "invalid value";
    }
    *field = (size_t) size;
    return NGX_CONF_OK;
}

static char *
ngx_stream_anytls_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;
    ngx_str_t *value;
    ngx_int_t n;
    ngx_uint_t *field;

    field = (ngx_uint_t *) (p + cmd->offset);
    if (*field != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR || n < 1) {
        return "invalid value";
    }
    *field = (ngx_uint_t) n;
    return NGX_CONF_OK;
}

static void
ngx_stream_anytls_handler(ngx_stream_session_t *s)
{
    ngx_stream_anytls_srv_conf_t *ascf;

    ascf = ngx_stream_get_module_srv_conf(s, ngx_stream_anytls_module);
    if (!ascf->enabled) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_anytls_connection_init(s, ascf);
}
