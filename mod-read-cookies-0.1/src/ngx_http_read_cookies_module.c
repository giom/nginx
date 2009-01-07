/*
 * http read cookies module.
 *
 * THIS SOFTWARE IS UNDER MIT LICENSE.
 * Copyright (C) 2008 Guy Naor - Morph Labs (guy@mor.ph)
 *
 * Read LICENSE file for more informations.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_read_cookies(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_cookie_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data); 

static ngx_command_t  ngx_http_read_cookies_commands[] = {

    { ngx_string("set_from_cookie"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2,
      ngx_http_read_cookies,
      0, 
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_read_cookies_module_ctx = {
    NULL,  NULL, NULL, NULL,  NULL, NULL, NULL, NULL 
};


ngx_module_t  ngx_http_read_cookies_module = {
    NGX_MODULE_V1,
    &ngx_http_read_cookies_module_ctx,       /* module context */
    ngx_http_read_cookies_commands,          /* module directives */
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


static char * ngx_http_read_cookies(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t           *value;
    unsigned char       *buff;
    ngx_http_variable_t *v;

    value = cf->args->elts;
        
    if (value[2].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    value[2].len--;
    value[2].data++;

    v = ngx_http_add_variable(cf, &value[2], 0); 
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL )
    {
        v->get_handler = ngx_http_cookie_variable;
        buff = ngx_palloc(cf->pool, value[1].len + 1);
        ngx_cpystrn(buff, value[1].data, value[1].len + 1);
        v->data = (uintptr_t)buff;
         
    } else { 
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "variable already defined as a non-cookie variable: \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_cookie_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) 
{
  ngx_str_t name = { ngx_strlen(data), (unsigned char *)data };
  ngx_str_t val = ngx_null_string;
  int n;

  n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &name, &val);

  if (n == NGX_DECLINED) {
    return n;
  }

  v->data = ngx_palloc(r->pool, val.len + 1);
  memcpy(v->data, val.data, val.len);
  v->data[val.len] = 0;
  v->len  = val.len;

  /* Set all required params */
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  return NGX_OK;
}


