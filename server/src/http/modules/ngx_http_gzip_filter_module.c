
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


typedef struct {
    ngx_flag_t           enable;
    ngx_flag_t           no_buffer;

    ngx_array_t         *types;     /* array of ngx_str_t */

    ngx_bufs_t           bufs;

    ngx_int_t            level;
    size_t               wbits;
    size_t               memlevel;
    ssize_t              min_length;
} ngx_http_gzip_conf_t;


typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;
    ngx_buf_t           *in_buf;
    ngx_buf_t           *out_buf;
    ngx_int_t            bufs;

    off_t                length;

    void                *preallocated;
    char                *free_mem;
    ngx_uint_t           allocated;

    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;

    size_t               zin;
    size_t               zout;

    uint32_t             crc32;
    z_stream             zstream;
    ngx_http_request_t  *request;
} ngx_http_gzip_ctx_t;


static void *ngx_http_gzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void ngx_http_gzip_filter_free(void *opaque, void *address);
static void ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx);

static ngx_int_t ngx_http_gzip_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_gzip_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_gzip_filter_init(ngx_conf_t *cf);
static void *ngx_http_gzip_create_conf(ngx_conf_t *cf);
static char *ngx_http_gzip_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_gzip_types(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_gzip_hash(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_num_bounds_t  ngx_http_gzip_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 9
};

static ngx_conf_post_handler_pt  ngx_http_gzip_window_p = ngx_http_gzip_window;
static ngx_conf_post_handler_pt  ngx_http_gzip_hash_p = ngx_http_gzip_hash;


static ngx_command_t  ngx_http_gzip_filter_commands[] = {

    { ngx_string("gzip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, enable),
      NULL },

    { ngx_string("gzip_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, bufs),
      NULL },

    { ngx_string("gzip_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_gzip_types,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("gzip_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, level),
      &ngx_http_gzip_comp_level_bounds },

    { ngx_string("gzip_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, wbits),
      &ngx_http_gzip_window_p },

    { ngx_string("gzip_hash"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, memlevel),
      &ngx_http_gzip_hash_p },

    { ngx_string("gzip_no_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, no_buffer),
      NULL },

    { ngx_string("gzip_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_conf_t, min_length),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_gzip_filter_module_ctx = {
    ngx_http_gzip_add_variables,           /* preconfiguration */
    ngx_http_gzip_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_gzip_create_conf,             /* create location configuration */
    ngx_http_gzip_merge_conf               /* merge location configuration */
};


ngx_module_t  ngx_http_gzip_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_gzip_filter_module_ctx,      /* module context */
    ngx_http_gzip_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char  gzheader[10] = { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };

#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

struct gztrailer {
    uint32_t  crc32;
    uint32_t  zlen;
};

#else /* NGX_HAVE_BIG_ENDIAN || !NGX_HAVE_NONALIGNED */

struct gztrailer {
    u_char  crc32[4];
    u_char  zlen[4];
};

#endif


static ngx_str_t  ngx_http_gzip_ratio = ngx_string("gzip_ratio");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_gzip_header_filter(ngx_http_request_t *r)
{
    ngx_str_t                 *type;
    ngx_uint_t                 i;
    ngx_table_elt_t           *h;
    ngx_http_gzip_ctx_t       *ctx;
    ngx_http_gzip_conf_t      *conf;
    ngx_http_core_loc_conf_t  *clcf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if ((r->headers_out.status != NGX_HTTP_OK
         && r->headers_out.status != NGX_HTTP_FORBIDDEN
         && r->headers_out.status != NGX_HTTP_NOT_FOUND)
        || r->header_only
        || r->headers_out.content_type.len == 0)
    {
        return ngx_http_next_header_filter(r);
    }

    if (!r->gunzip) {
        if (!conf->enable
            || (r->headers_out.content_encoding
                && r->headers_out.content_encoding->value.len)
            || (r->headers_out.content_length_n != -1
                && r->headers_out.content_length_n < conf->min_length)
            || ngx_http_gzip_ok(r) != NGX_OK)
        {
            return ngx_http_next_header_filter(r);
        }

        type = conf->types->elts;
        for (i = 0; i < conf->types->nelts; i++) {
            if (r->headers_out.content_type.len >= type[i].len
                && ngx_strncasecmp(r->headers_out.content_type.data,
                                   type[i].data, type[i].len) == 0)
            {
                goto found;
            }
        }

        return ngx_http_next_header_filter(r);
    }

found:

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_gzip_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_gzip_filter_module);

    ctx->request = r;

    if (!r->gunzip) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;
        h->key.len = sizeof("Content-Encoding") - 1;
        h->key.data = (u_char *) "Content-Encoding";
        h->value.len = sizeof("gzip") - 1;
        h->value.data = (u_char *) "gzip";

        r->headers_out.content_encoding = h;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->gzip_vary) {
            h = ngx_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = 1;
            h->key.len = sizeof("Vary") - 1;
            h->key.data = (u_char *) "Vary";
            h->value.len = sizeof("Accept-Encoding") - 1;
            h->value.data = (u_char *) "Accept-Encoding";
        }
    }

    ctx->length = r->headers_out.content_length_n;

    r->main_filter_need_in_memory = 1;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_gzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                    rc, wbits, memlevel;
    ngx_int_t              last;
    struct gztrailer      *trailer;
    ngx_buf_t             *b;
    ngx_chain_t           *cl, out;
    ngx_http_gzip_ctx_t   *ctx;
    ngx_http_gzip_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);

    if (ctx->preallocated == NULL) {
        wbits = conf->wbits;
        memlevel = conf->memlevel;

        if (ctx->length > 0) {

            /* the actual zlib window size is smaller by 262 bytes */

            while (ctx->length < ((1 << (wbits - 1)) - 262)) {
                wbits--;
                memlevel--;
            }
        }

        /*
         * We preallocate a memory for zlib in one buffer (200K-400K), this
         * decreases a number of malloc() and free() calls and also probably
         * decreases a number of syscalls (sbrk() and so on).
         * Besides we free this memory as soon as the gzipping will complete
         * and do not wait while a whole response will be sent to a client.
         *
         * 8K is for zlib deflate_state, it takes
         *  *) 5816 bytes on i386 and sparc64 (32-bit mode)
         *  *) 5920 bytes on amd64 and sparc64
         */

        ctx->allocated = 8192 + (1 << (wbits + 2)) + (1 << (memlevel + 9));

        ctx->preallocated = ngx_palloc(r->pool, ctx->allocated);
        if (ctx->preallocated == NULL) {
            return NGX_ERROR;
        }

        ctx->free_mem = ctx->preallocated;

        ctx->zstream.zalloc = ngx_http_gzip_filter_alloc;
        ctx->zstream.zfree = ngx_http_gzip_filter_free;
        ctx->zstream.opaque = ctx;

        if (!r->gunzip) {
            rc = deflateInit2(&ctx->zstream, (int) conf->level, Z_DEFLATED,
                              -wbits, memlevel, Z_DEFAULT_STRATEGY);
        } else {
            rc = inflateInit2(&ctx->zstream, 15 + 16);
        }

        if (rc != Z_OK) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "deflateInit2() failed: %d", rc);
            ngx_http_gzip_error(ctx);
            return NGX_ERROR;
        }

        if (!r->gunzip) {
            b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
            if (b == NULL) {
                ngx_http_gzip_error(ctx);
                return NGX_ERROR;
            }

            b->memory = 1;
            b->pos = gzheader;
            b->last = b->pos + 10;

            out.buf = b;
            out.next = NULL;

            /*
             * We pass the gzheader to the next filter now to avoid
             * its linking to the ctx->busy chain.  zlib does not
             * usually output the compressed data in the initial
             * iterations, so the gzheader that was linked to the
             * ctx->busy chain would be flushed by
             * ngx_http_write_filter().
             */

            if (ngx_http_next_body_filter(r, &out) == NGX_ERROR) {
                ngx_http_gzip_error(ctx);
                return NGX_ERROR;
            }

            ctx->crc32 = crc32(0L, Z_NULL, 0);
        }

        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;

        ctx->last_out = &ctx->out;

        ctx->flush = Z_NO_FLUSH;
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            ngx_http_gzip_error(ctx);
            return NGX_ERROR;
        }
    }

    last = NGX_NONE;

    for ( ;; ) {

        for ( ;; ) {

            /* does zlib need a new data ? */

            if (ctx->zstream.avail_in == 0
                && ctx->flush == Z_NO_FLUSH
                && !ctx->redo)
            {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "gzip in: %p", ctx->in);

                if (ctx->in == NULL) {
                    break;
                }

                ctx->in_buf = ctx->in->buf;
                ctx->in = ctx->in->next;

                ctx->zstream.next_in = ctx->in_buf->pos;
                ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "gzip in_buf:%p ni:%p ai:%ud",
                               ctx->in_buf,
                               ctx->zstream.next_in, ctx->zstream.avail_in);

                /* STUB */
                if (ctx->in_buf->last < ctx->in_buf->pos) {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                  "zstream.avail_in is huge");
                    ctx->done = 1;
                    return NGX_ERROR;
                }
                /**/

                if (ctx->in_buf->last_buf) {
                    ctx->flush = Z_FINISH;

                } else if (ctx->in_buf->flush) {
                    ctx->flush = Z_SYNC_FLUSH;
                }

                if (ctx->zstream.avail_in == 0) {
                    if (ctx->flush == Z_NO_FLUSH) {
                        continue;
                    }

                } else if (!r->gunzip) {
                    ctx->crc32 = crc32(ctx->crc32, ctx->zstream.next_in,
                                       ctx->zstream.avail_in);
                }
            }


            /* is there a space for the gzipped data ? */

            if (ctx->zstream.avail_out == 0) {

                if (ctx->free) {
                    ctx->out_buf = ctx->free->buf;
                    ctx->free = ctx->free->next;

                } else if (ctx->bufs < conf->bufs.num) {
                    ctx->out_buf = ngx_create_temp_buf(r->pool,
                                                       conf->bufs.size);
                    if (ctx->out_buf == NULL) {
                        ngx_http_gzip_error(ctx);
                        return NGX_ERROR;
                    }

                    ctx->out_buf->tag = (ngx_buf_tag_t)
                                                  &ngx_http_gzip_filter_module;
                    ctx->out_buf->recycled = 1;
                    ctx->bufs++;

                } else {
                    break;
                }

                ctx->zstream.next_out = ctx->out_buf->pos;
                ctx->zstream.avail_out = conf->bufs.size;
            }

            ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                         "deflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                         ctx->zstream.next_in, ctx->zstream.next_out,
                         ctx->zstream.avail_in, ctx->zstream.avail_out,
                         ctx->flush, ctx->redo);

            if (!r->gunzip) {
                rc = deflate(&ctx->zstream, ctx->flush);
            } else {
                rc = inflate(&ctx->zstream, ctx->flush);
            }

            if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "deflate() failed: %d, %d", ctx->flush, rc);
                ngx_http_gzip_error(ctx);
                return NGX_ERROR;
            }

            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                           ctx->zstream.next_in, ctx->zstream.next_out,
                           ctx->zstream.avail_in, ctx->zstream.avail_out,
                           rc);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "gzip in_buf:%p pos:%p",
                           ctx->in_buf, ctx->in_buf->pos);


            if (ctx->zstream.next_in) {
                ctx->in_buf->pos = ctx->zstream.next_in;

                if (ctx->zstream.avail_in == 0) {
                    ctx->zstream.next_in = NULL;
                }
            }

            ctx->out_buf->last = ctx->zstream.next_out;

            ctx->redo = 0;

            if (ctx->flush == Z_SYNC_FLUSH
                && ctx->out_buf->last > ctx->out_buf->pos) {

                ctx->zstream.avail_out = 0;
                ctx->out_buf->flush = 1;
                ctx->flush = Z_NO_FLUSH;

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    ngx_http_gzip_error(ctx);
                    return NGX_ERROR;
                }

                cl->buf = ctx->out_buf;
                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                break;
            }

            if (rc == Z_STREAM_END) {

                ctx->zin = ctx->zstream.total_in;
                if (!r->gunzip) {
                    ctx->zout = 10 + ctx->zstream.total_out + 8;

                    rc = deflateEnd(&ctx->zstream);
                } else {
                    ctx->zout = ctx->zstream.total_out;

                    rc = inflateEnd(&ctx->zstream);
                }

                if (rc != Z_OK) {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                  "deflateEnd() failed: %d", rc);
                    ngx_http_gzip_error(ctx);
                    return NGX_ERROR;
                }

                ngx_pfree(r->pool, ctx->preallocated);

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    ngx_http_gzip_error(ctx);
                    return NGX_ERROR;
                }

                cl->buf = ctx->out_buf;
                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                if (!r->gunzip) {
                    if (ctx->zstream.avail_out >= 8) {
                        trailer = (struct gztrailer *) ctx->out_buf->last;
                        ctx->out_buf->last += 8;
                        ctx->out_buf->last_buf = 1;

                    } else {
                        b = ngx_create_temp_buf(r->pool, 8);
                        if (b == NULL) {
                            ngx_http_gzip_error(ctx);
                            return NGX_ERROR;
                        }

                        b->last_buf = 1;

                        cl = ngx_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            ngx_http_gzip_error(ctx);
                            return NGX_ERROR;
                        }

                        cl->buf = b;
                        cl->next = NULL;
                        *ctx->last_out = cl;
                        ctx->last_out = &cl->next;
                        trailer = (struct gztrailer *) b->pos;
                        b->last += 8;
                    }

#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

                    trailer->crc32 = ctx->crc32;
                    trailer->zlen = ctx->zin;

#else
                    trailer->crc32[0] = (u_char) (ctx->crc32 & 0xff);
                    trailer->crc32[1] = (u_char) ((ctx->crc32 >> 8) & 0xff);
                    trailer->crc32[2] = (u_char) ((ctx->crc32 >> 16) & 0xff);
                    trailer->crc32[3] = (u_char) ((ctx->crc32 >> 24) & 0xff);

                    trailer->zlen[0] = (u_char) (ctx->zin & 0xff);
                    trailer->zlen[1] = (u_char) ((ctx->zin >> 8) & 0xff);
                    trailer->zlen[2] = (u_char) ((ctx->zin >> 16) & 0xff);
                    trailer->zlen[3] = (u_char) ((ctx->zin >> 24) & 0xff);
#endif
                } else {
                    ctx->out_buf->last_buf = 1;
                    r->gunzip = 0;
                }

                ctx->zstream.avail_in = 0;
                ctx->zstream.avail_out = 0;

                ctx->done = 1;

                r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

                break;
            }

            if (ctx->zstream.avail_out == 0) {

                /* zlib wants to output some more gzipped data */

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    ngx_http_gzip_error(ctx);
                    return NGX_ERROR;
                }

                cl->buf = ctx->out_buf;
                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->redo = 1;

                continue;
            }

            if (conf->no_buffer && ctx->in == NULL) {

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    ngx_http_gzip_error(ctx);
                    return NGX_ERROR;
                }

                cl->buf = ctx->out_buf;
                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                break;
            }
        }

        if (ctx->out == NULL) {

            if (last == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (ctx->busy == NULL) {
                return NGX_OK;
            }
        }

        last = ngx_http_next_body_filter(r, ctx->out);

        /*
         * we do not check NGX_AGAIN here because the downstream filters
         * may free some buffers and zlib may compress some data into them
         */

        if (last == NGX_ERROR) {
            ngx_http_gzip_error(ctx);
            return NGX_ERROR;
        }

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_gzip_filter_module);
        ctx->last_out = &ctx->out;

        if (ctx->done) {
            return last;
        }
    }
}


static void *
ngx_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    ngx_http_gzip_ctx_t *ctx = opaque;

    void        *p;
    ngx_uint_t   alloc;

    alloc = items * size;

    if (alloc % 512 != 0) {

        /*
         * The zlib deflate_state allocation, it takes about 6K,
         * we allocate 8K.  Other allocations are divisible by 512.
         */

        alloc = (alloc + ngx_pagesize - 1) & ~(ngx_pagesize - 1);
    }

    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                       "gzip alloc: n:%ud s:%ud a:%ud p:%p",
                       items, size, alloc, p);

        return p;
    }

    ngx_log_error(NGX_LOG_ALERT, ctx->request->connection->log, 0,
                  "gzip filter failed to use preallocated memory: %ud of %ud",
                  items * size, ctx->allocated);

    p = ngx_palloc(ctx->request->pool, items * size);

    return p;
}


static void
ngx_http_gzip_filter_free(void *opaque, void *address)
{
#if 0
    ngx_http_gzip_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gzip free: %p", address);
#endif
}


static void
ngx_http_gzip_error(ngx_http_gzip_ctx_t *ctx)
{
    if (! ctx->request->gunzip) {
        deflateEnd(&ctx->zstream);
    } else {
        ctx->request->gunzip = 0;
        inflateEnd(&ctx->zstream);
    }

    if (ctx->preallocated) {
        ngx_pfree(ctx->request->pool, ctx->preallocated);
    }

    ctx->zstream.avail_in = 0;
    ctx->zstream.avail_out = 0;

    ctx->done = 1;

    return;
}


static ngx_int_t
ngx_http_gzip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_gzip_ratio, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_gzip_ratio_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_gzip_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t            zint, zfrac;
    ngx_http_gzip_ctx_t  *ctx;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);

    if (ctx == NULL || ctx->zout == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_palloc(r->pool, NGX_INT32_LEN + 3);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    zint = (ngx_uint_t) (ctx->zin / ctx->zout);
    zfrac = (ngx_uint_t) ((ctx->zin * 100 / ctx->zout) % 100);

    if ((ctx->zin * 1000 / ctx->zout) % 10 > 4) {

        /* the rounding, e.g., 2.125 to 2.13 */

        zfrac++;

        if (zfrac > 99) {
            zint++;
            zfrac = 0;
        }
    }

    v->len = ngx_sprintf(v->data, "%ui.%02ui", zint, zfrac) - v->data;

    return NGX_OK;
}


static void *
ngx_http_gzip_create_conf(ngx_conf_t *cf)
{
    ngx_http_gzip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gzip_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->types = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->no_buffer = NGX_CONF_UNSET;

    conf->level = NGX_CONF_UNSET;
    conf->wbits = (size_t) NGX_CONF_UNSET;
    conf->memlevel = (size_t) NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_gzip_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_gzip_conf_t *prev = parent;
    ngx_http_gzip_conf_t *conf = child;

    ngx_str_t  *type;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 4, ngx_pagesize);

    ngx_conf_merge_value(conf->level, prev->level, 1);
    ngx_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    ngx_conf_merge_size_value(conf->memlevel, prev->memlevel,
                              MAX_MEM_LEVEL - 1);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);
    ngx_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    if (conf->types == NULL) {
        if (prev->types == NULL) {
            conf->types = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
            if (conf->types == NULL) {
                return NGX_CONF_ERROR;
            }

            type = ngx_array_push(conf->types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->len = sizeof("text/html") - 1;
            type->data = (u_char *) "text/html";

        } else {
            conf->types = prev->types;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_gzip_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_gzip_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_gzip_body_filter;

    return NGX_OK;
}


static char *
ngx_http_gzip_types(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_gzip_conf_t *gcf = conf;

    ngx_str_t   *value, *type;
    ngx_uint_t   i;

    if (gcf->types == NULL) {
        gcf->types = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (gcf->types == NULL) {
            return NGX_CONF_ERROR;
        }

        type = ngx_array_push(gcf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = sizeof("text/html") - 1;
        type->data = (u_char *) "text/html";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "text/html") == 0) {
            continue;
        }

        type = ngx_array_push(gcf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = value[i].len;

        type->data = ngx_palloc(cf->pool, type->len + 1);
        if (type->data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_cpystrn(type->data, value[i].data, type->len + 1);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data)
{
    int *np = data;

    int  wbits, wsize;

    wbits = 15;

    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return NGX_CONF_OK;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
}


static char *
ngx_http_gzip_hash(ngx_conf_t *cf, void *post, void *data)
{
    int *np = data;

    int  memlevel, hsize;

    memlevel = 9;

    for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {

        if (hsize == *np) {
            *np = memlevel;

            return NGX_CONF_OK;
        }

        memlevel--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
}
