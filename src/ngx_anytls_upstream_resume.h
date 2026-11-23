#ifndef NGX_ANYTLS_UPSTREAM_RESUME_H_INCLUDED
#define NGX_ANYTLS_UPSTREAM_RESUME_H_INCLUDED

typedef enum {
    NGX_ANYTLS_UPSTREAM_RESUME_NONE = 0,
    NGX_ANYTLS_UPSTREAM_RESUME_ARM,
    NGX_ANYTLS_UPSTREAM_RESUME_POST
} ngx_anytls_upstream_resume_action_e;

static inline ngx_anytls_upstream_resume_action_e
ngx_anytls_upstream_resume_action(unsigned ready, unsigned posted)
{
    if (ready == 0) {
        return NGX_ANYTLS_UPSTREAM_RESUME_ARM;
    }

    return posted != 0 ? NGX_ANYTLS_UPSTREAM_RESUME_NONE
                       : NGX_ANYTLS_UPSTREAM_RESUME_POST;
}

#endif /* NGX_ANYTLS_UPSTREAM_RESUME_H_INCLUDED */
