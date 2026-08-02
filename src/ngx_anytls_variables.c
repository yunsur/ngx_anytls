/*
 * Expose AnyTLS session metadata as stream variables, for use in stream
 * access logs (and other log_format contexts):
 *
 *   $anytls_user   authenticated user name; not-found when the
 *                  connection did not authenticate (logs show "-")
 *   $anytls_version  client AnyTLS version after SETTINGS; otherwise "-"
 *   $anytls_auth   auth result: ok/fallback/timeout/error, or "-"
 *
 * The variable evaluates against the module's connection context, so it
 * is only meaningful on sessions handled by this module; on any other
 * stream session it resolves to not-found.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_anytls_connection_private.h"
#include "ngx_anytls_variables.h"
#include "ngx_stream_anytls_module.h"


static ngx_str_t ngx_anytls_auth_values[] = {
    ngx_null_string,
    ngx_string("ok"),
    ngx_string("fallback"),
    ngx_string("timeout"),
    ngx_string("error")
};


static void
ngx_anytls_variable_set(ngx_stream_variable_value_t *v, ngx_str_t *value)
{
    v->len = value->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = value->data;
}


static ngx_int_t
ngx_anytls_variable_str(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_anytls_connection_t *ac;
    ngx_str_t *value;

    ac = ngx_stream_get_module_ctx(s, ngx_stream_anytls_module);
    if (ac == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    value = (ngx_str_t *) ((u_char *) ac + data);
    if (value->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_anytls_variable_set(v, value);

    return NGX_OK;
}


static ngx_int_t
ngx_anytls_variable_auth(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_anytls_connection_t *ac;

    (void) data;

    ac = ngx_stream_get_module_ctx(s, ngx_stream_anytls_module);
    if (ac == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ac->auth_status == NGX_ANYTLS_AUTH_STATUS_UNSET
        || ac->auth_status > NGX_ANYTLS_AUTH_STATUS_ERROR)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_anytls_variable_set(v, &ngx_anytls_auth_values[ac->auth_status]);

    return NGX_OK;
}


/* NOCACHEABLE: the value changes with connection state (not-found
 * before auth, user name after), so early evaluations in limit_conn /
 * map / complex-value contexts must not stick for the access-log read */
static ngx_stream_variable_t ngx_anytls_variables[] = {
    { ngx_string("anytls_user"), NULL, ngx_anytls_variable_str,
      offsetof(ngx_anytls_connection_t, user_name),
      NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("anytls_version"), NULL, ngx_anytls_variable_str,
      offsetof(ngx_anytls_connection_t, version_text),
      NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("anytls_auth"), NULL, ngx_anytls_variable_auth, 0,
      NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


ngx_int_t
ngx_anytls_variables_preconfiguration(ngx_conf_t *cf)
{
    ngx_stream_variable_t *var, *av;

    /* register at preconfiguration time so log_format / access_log
     * directives parsed later in the config can index the variables */
    for (av = ngx_anytls_variables; av->name.len; av++) {
        var = ngx_stream_add_variable(cf, &av->name, av->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = av->get_handler;
        var->data = av->data;
    }

    return NGX_OK;
}
