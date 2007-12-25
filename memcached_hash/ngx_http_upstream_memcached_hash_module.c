/*
  Copyright (C) 2007 Tomash Brechko.  All rights reserved.

  Development of this module is sponsored by Monashev Co. Ltd.

  This file is distributed on the same terms as the rest of nginx
  source code.

  Version 0.01.
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define CONTINUUM_MAX_POINT  0xffffffffU


struct memcached_hash_continuum
{
  unsigned int point;
  unsigned int index;
};


struct memcached_hash_peer
{
  ngx_http_upstream_server_t *server;
  unsigned int addr_index;
  time_t accessed;
  unsigned int fails;
};


struct memcached_hash
{
  struct memcached_hash_continuum *bins;
  struct memcached_hash_peer *peers;
  unsigned int bins_count;
  unsigned int peer_count;
  unsigned int total_weight;
  unsigned int ketama_points;
  unsigned int scale;
};


struct memcached_hash_find_ctx
{
  struct memcached_hash *memd;
  ngx_http_upstream_server_t *server;
  ngx_chain_t **request_bufs;
};


static
unsigned int
memcached_hash_find_bin(struct memcached_hash *memd, unsigned int point)
{
  struct memcached_hash_continuum *left, *right;

  left = memd->bins;
  right = memd->bins + memd->bins_count;

  while (left < right)
    {
      struct memcached_hash_continuum *middle = left + (right - left) / 2;
      if (middle->point < point)
        left = middle + 1;
      else if (middle->point > point)
        right = middle;
      else
        return (middle - memd->bins);
    }

  /* Wrap around.  */
  if (left == memd->bins + memd->bins_count)
    left = memd->bins;

  return (left - memd->bins);
}


static
ngx_int_t
memcached_hash_get_peer(ngx_peer_connection_t *pc, void *data)
{
  struct memcached_hash_peer *peer = data;
  ngx_peer_addr_t *addr;

  if (peer->server->down)
    goto fail;

  if (peer->server->max_fails > 0 && peer->fails >= peer->server->max_fails)
    {
      time_t now = ngx_time();
      if (now - peer->accessed <= peer->server->fail_timeout)
        goto fail;
      else
        peer->fails = 0;
    }

  addr = &peer->server->addrs[peer->addr_index];

  pc->sockaddr = addr->sockaddr;
  pc->socklen = addr->socklen;
  pc->name = &addr->name;

  return NGX_OK;

fail:
  pc->tries = 0;

  return NGX_BUSY;
}


static
ngx_int_t
memcached_hash_find_peer(ngx_peer_connection_t *pc, void *data)
{
  struct memcached_hash_find_ctx *find_ctx = data;
  struct memcached_hash *memd = find_ctx->memd;
  u_char *key;
  size_t len;
  unsigned int point, bin, index;

  if (memd->peer_count == 1)
    {
      index = 0;
    }
  else
    {
      /*
        We take the key directly from request_buf, because there it is
        in the escaped form that will be seen by memcached server.
      */
      key = (*find_ctx->request_bufs)->buf->start + (sizeof("get ") - 1);
      len = (((*find_ctx->request_bufs)->buf->last - key)
             - (sizeof("\r\n") - 1));

      point = ngx_crc32_long(key, len);

      if (memd->ketama_points == 0)
        {
          point = ((point >> 16) & 0x00007fff);
          point = point % ((memd->total_weight + memd->scale / 2)
                           / memd->scale);
          point = ((uint64_t) point * CONTINUUM_MAX_POINT
                   + memd->total_weight / 2) / memd->total_weight;
          /*
            Shift point one step forward to possibly get from the
            border point which belongs to the previous bin.
          */
          point += 1;
        }

      bin = memcached_hash_find_bin(memd, point);
      index = memd->bins[bin].index;
    }

  pc->data = &memd->peers[index];
  pc->get = memcached_hash_get_peer;
  pc->tries = find_ctx->server[index].naddrs;

  return memcached_hash_get_peer(pc, pc->data);
}


static
void
memcached_hash_free_peer(ngx_peer_connection_t *pc, void *data,
                         ngx_uint_t state)
{
  struct memcached_hash_peer *peer = data;

  if (state == 0)
    {
      peer->accessed = ngx_time();
    }
  else if (state & NGX_PEER_FAILED)
    {
      ++peer->fails;
      if (--pc->tries > 0)
        {
          if (++peer->addr_index == peer->server->naddrs)
            peer->addr_index = 0;
        }
    }
}


static
ngx_int_t
memcached_hash_init_peer(ngx_http_request_t *r,
                         ngx_http_upstream_srv_conf_t *us)
{
  struct memcached_hash *memd = us->peer.data;
  struct memcached_hash_find_ctx *find_ctx;

  find_ctx = ngx_palloc(r->pool, sizeof(*find_ctx));
  if (! find_ctx)
    return NGX_ERROR;
  find_ctx->memd = memd;
  find_ctx->request_bufs = &r->upstream->request_bufs;
  find_ctx->server = us->servers->elts;

  r->upstream->peer.free = memcached_hash_free_peer;

  /*
    The following values will be replaced by
    memcached_hash_find_peer().
  */
  r->upstream->peer.get = memcached_hash_find_peer;
  r->upstream->peer.data = find_ctx;
  r->upstream->peer.tries = 1;

  return NGX_OK;
}


static
ngx_int_t
memcached_init_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
  struct memcached_hash *memd = us->peer.data;
  ngx_http_upstream_server_t *server;
  unsigned int bins_count, i;

  if (! us->servers)
    return NGX_ERROR;

  server = us->servers->elts;

  us->peer.init = memcached_hash_init_peer;

  memd->peers = ngx_palloc(cf->pool,
                           sizeof(*memd->peers) * us->servers->nelts);
  if (! memd->peers)
    return NGX_ERROR;

  memd->total_weight = 0;

  for (i = 0; i < us->servers->nelts; i++)
    {
      memd->total_weight += server[i].weight;
      ngx_memzero(&memd->peers[i], sizeof(memd->peers[i]));
      memd->peers[i].server = &server[i];
    }
  memd->peer_count = us->servers->nelts;

  if (memd->ketama_points == 0)
    {
      bins_count = us->servers->nelts;
    }
  else
    {
      bins_count = 0;
      for (i = 0; i < us->servers->nelts; i++)
        bins_count += (memd->ketama_points * server[i].weight
                       + memd->scale / 2) / memd->scale;
    }

  memd->bins = ngx_palloc(cf->pool, sizeof(*memd->bins) * bins_count);
  if (! memd->bins)
    return NGX_ERROR;
  memd->bins_count = bins_count;

  if (memd->ketama_points == 0)
    {
      ngx_uint_t offset = 0;
      for (i = 0; i < us->servers->nelts; i++)
        {
          memd->bins[i].point =
            offset + ((uint64_t) CONTINUUM_MAX_POINT * server[i].weight
                      + memd->total_weight / 2) / memd->total_weight;
          offset = memd->bins[i].point;
          memd->bins[i].index = i;
        }
    }
  else
    {
      for (i = 0; i < us->servers->nelts; i++)
        {
          static const char delim = '\0';
          char *host, *port;
          size_t len, port_len = 0;
          unsigned int crc32, count, j;

          host = server[i].addrs[0].name.data;
          len = server[i].addrs[0].name.len;

#if (NGX_HAVE_UNIX_DOMAIN)
          if (ngx_strncasecmp(host, "unix:", 5) == 0)
            {
              host += 5;
              len -= 5;
            }
#endif

          port = host;
          while (*port)
            {
              if (*port++ == ':')
                {
                  port_len = len - (port - host);
                  len = (port - host) - 1;
                  break;
                }
            }

          ngx_crc32_init(crc32);
          ngx_crc32_update(&crc32, host, len);
          ngx_crc32_update(&crc32, (char *) &delim, 1);
          ngx_crc32_update(&crc32, port, port_len);

          count = (memd->ketama_points * server[i].weight
                   + memd->scale / 2) / memd->scale;
          bins_count = 0;
          for (j = 0; j < count; j++)
            {
              char buf[4];
              unsigned int point = crc32, bin;

              /*
                We want the same result on all platforms, so we
                hardcode size of int as 4 8-bit bytes.
              */
              buf[0] = j & 0xff;
              buf[1] = (j >> 8) & 0xff;
              buf[2] = (j >> 16) & 0xff;
              buf[3] = (j >> 24) & 0xff;

              ngx_crc32_update(&point, buf, 4);
              ngx_crc32_final(point);

              if (bins_count > 0)
                {
                  bin = memcached_hash_find_bin(memd, point);

                  /*
                    Check if we wrapped around but actually have new
                    max point.
                  */
                  if (bin == 0 && point > memd->bins[0].point)
                    {
                      bin = memd->bins_count;
                    }
                  else
                    {
                      if (point == memd->bins[bin].point)
                        {
                          /*
                            Even if there's a server for the same
                            point already, we have to add ours,
                            because the first one may be removed
                            later.  But we add ours after the first
                            server for not to change key distribution.
                            */
                          ++bin;
                        }

                      /* Move the tail one position forward.  */
                      ngx_memmove(memd->bins + bin + 1, memd->bins + bin,
                                  ((memd->bins_count - bin)
                                   * sizeof(*memd->bins)));
                    }
                }
              else
                {
                  bin = 0;
                }

              memd->bins[bin].point = point;
              memd->bins[bin].index = i;

              ++bins_count;
            }
        }
    }

  return NGX_OK;
}


static
char *
memcached_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_str_t *value = cf->args->elts;
  ngx_http_upstream_srv_conf_t *uscf;
  struct memcached_hash *memd;
  int ketama_points, scale;
  unsigned int i;

  ketama_points = 0;
  scale = 1;

  uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

  for (i = 1; i < cf->args->nelts; i++)
    {
      if (ngx_strncmp(value[i].data, "ketama_points=", 14) == 0)
        {
          ketama_points = ngx_atoi(&value[i].data[14], value[i].len - 14);

          if (ketama_points == NGX_ERROR || ketama_points < 0)
            goto invalid;

          continue;
        }

      if (ngx_strncmp(value[i].data, "weight_scale=", 13) == 0)
        {
          scale = ngx_atoi(&value[i].data[13], value[i].len - 13);

          if (scale == NGX_ERROR || scale <= 0)
            goto invalid;

          continue;
        }

      goto invalid;
    }

  memd = ngx_palloc(cf->pool, sizeof(*memd));
  if (! memd)
    return "not enough memory";

  memd->ketama_points = ketama_points;
  memd->scale = scale;

  uscf->peer.data = memd;

  uscf->peer.init_upstream = memcached_init_hash;

  uscf->flags = (NGX_HTTP_UPSTREAM_CREATE
                 | NGX_HTTP_UPSTREAM_WEIGHT
                 | NGX_HTTP_UPSTREAM_MAX_FAILS
                 | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                 | NGX_HTTP_UPSTREAM_DOWN);

  return NGX_CONF_OK;

invalid:
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid parameter \"%V\"", &value[i]);

  return NGX_CONF_ERROR;
}


static ngx_command_t memcached_hash_commands[] = {
  {
    ngx_string("memcached_hash"),
    NGX_HTTP_UPS_CONF | NGX_CONF_ANY, /* Should be 0|1|2 params.  */
    memcached_hash,
    0,
    0,
    NULL
  },

  ngx_null_command
};


static ngx_http_module_t memcached_hash_module_ctx = {
  NULL,                         /* preconfiguration */
  NULL,                         /* postconfiguration */

  NULL,                         /* create main configuration */
  NULL,                         /* init main configuration */

  NULL,                         /* create server configuration */
  NULL,                         /* merge server configuration */

  NULL,                         /* create location configuration */
  NULL                          /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_memcached_hash_module = {
  NGX_MODULE_V1,
  &memcached_hash_module_ctx,   /* module context */
  memcached_hash_commands,      /* module directives */
  NGX_HTTP_MODULE,              /* module type */
  NULL,                         /* init master */
  NULL,                         /* init module */
  NULL,                         /* init process */
  NULL,                         /* init thread */
  NULL,                         /* exit thread */
  NULL,                         /* exit process */
  NULL,                         /* exit master */
  NGX_MODULE_V1_PADDING
};
