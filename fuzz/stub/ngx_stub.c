/* Minimal standalone stubs for fuzzing ngx_anytls parse functions
 * without linking the full nginx runtime.
 *
 * Implements a tiny arena pool (real allocations, freed on destroy) and the
 * ngx_* / config-file symbols the module sources reference, so the fuzz
 * binaries link with only libc + OpenSSL.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>


typedef struct fuzz_large_s {
    void                *ptr;
    struct fuzz_large_s *next;
} fuzz_large_t;

typedef struct {
    u_char       *start;
    u_char       *pos;
    u_char       *end;
    fuzz_large_t *large;
} fuzz_pool_t;


void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;
    return malloc(size);
}


ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    fuzz_pool_t *p;

    (void) log;

    if (size < 256) {
        size = 256;
    }

    p = malloc(sizeof(fuzz_pool_t) + size);
    if (p == NULL) {
        return NULL;
    }

    p->start = (u_char *) (p + 1);
    p->pos = p->start;
    p->end = p->start + size;
    p->large = NULL;

    return (ngx_pool_t *) p;
}


void
ngx_destroy_pool(ngx_pool_t *pool)
{
    fuzz_pool_t *p = (fuzz_pool_t *) pool;
    fuzz_large_t *l, *next;

    if (p == NULL) {
        return;
    }

    for (l = p->large; l != NULL; l = next) {
        next = l->next;
        free(l->ptr);
        free(l);
    }

    free(p);
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    fuzz_pool_t *p = (fuzz_pool_t *) pool;
    fuzz_large_t *l;
    size_t aligned;
    void *r;

    aligned = (size + 15) & ~(size_t) 15;

    if ((size_t) (p->end - p->pos) >= aligned) {
        r = p->pos;
        p->pos += aligned;
        return r;
    }

    l = malloc(sizeof(fuzz_large_t));
    if (l == NULL) {
        return NULL;
    }

    l->ptr = malloc(size ? size : 1);
    if (l->ptr == NULL) {
        free(l);
        return NULL;
    }

    l->next = p->large;
    p->large = l;
    return l->ptr;
}


void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    return ngx_palloc(pool, size);
}


void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p = ngx_palloc(pool, size);

    if (p != NULL) {
        memset(p, 0, size);
    }

    return p;
}


ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    return strncasecmp((const char *) s1, (const char *) s2, n);
}


size_t
ngx_inet_ntop(int family, void *addr, u_char *text, size_t len)
{
    if (inet_ntop(family, addr, (char *) text, len) == NULL) {
        return 0;
    }

    return ngx_strlen(text);
}


ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t value;
    ngx_uint_t i;

    if (n == 0) {
        return NGX_ERROR;
    }

    value = 0;

    for (i = 0; i < n; i++) {
        if (line[i] < '0' || line[i] > '9') {
            return NGX_ERROR;
        }
        value = value * 10 + (line[i] - '0');
    }

    return value;
}


u_char *
ngx_sprintf(u_char *buf, const char *fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vsnprintf((char *) buf, NGX_INT64_LEN + 10, fmt, args);
    va_end(args);

    if (n < 0) {
        return buf;
    }

    return buf + n;
}


ngx_int_t
ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u)
{
    (void) pool;
    (void) u;
    return NGX_ERROR;
}


ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    (void) file;
    (void) buf;
    (void) size;
    (void) offset;
    return NGX_ERROR;
}


void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level;
    (void) cf;
    (void) err;
    (void) fmt;
}
