/*
 * Created by yobol on 2020/6/10.
 *
 * Build stable relations between pipeline instances and model services.
 */

#include <ngx_http_config.h>

static ngx_int_t ngx_http_upstream_init_tw_bind_peer(ngx_http_request_t *r,
        ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_tw_bind_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_srv_conf_t *us);
static char *ngx_http_upstream_tw_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_upstream_tw_bind_commands[] = {
        {
                // config name in nginx.conf
                ngx_string("tw_bind"),
                // only allowed to existing in upstream configure block
                // only take one argument
                // e.g.
                // upstream {
                //    tw_bind $http_x_instance_id
                // }
                NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
                // callback
                ngx_http_upstream_tw_bind,
                0,
                0,
                NULL
        },
        ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_tw_bind_module_ctx = {
        NULL,                                  /* preconfiguration */
        NULL,                                  /* postconfiguration */

        NULL,                                  /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                  /* create location configuration */
        NULL                                   /* merge location configuration */
};

ngx_module_t ngx_http_upstream_tw_bind_module = {
        NGX_MODULE_V1,
        &ngx_http_upstream_tw_bind_module_ctx,  /* module context */
        ngx_http_upstream_tw_bind_commands,  /* module directives */
        NGX_HTTP_MODULE,  /* module type */
        NULL,                                  /* init module */
        NULL,                                  /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_upstream_init_tw_bind_peer(ngx_http_request_t *r,
        ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init TransWarp Sophon Edge bind peer");

}

static ngx_int_t
ngx_http_upstream_get_tw_bind_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_srv_conf_t *t)
{

}

static char *
ngx_http_upstream_tw_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

}