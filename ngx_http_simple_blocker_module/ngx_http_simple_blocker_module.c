#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t                 match;
    ngx_str_t                 type;
    ngx_str_t                 pattern;
} ngx_http_simple_blocker_module_conf_t;

typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
} ngx_http_simple_blocker_module_ctx_t;

typedef struct {
    ngx_int_t                 index;
    ngx_http_complex_value_t  value;
    ngx_http_set_variable_pt  set_handler;
} ngx_http_simple_blocker_module_variable_t;

static ngx_int_t ngx_http_simple_blocker_module_handler(ngx_http_request_t *r);
static void *ngx_http_simple_blocker_module_create_conf(ngx_conf_t *cf);
static char *ngx_http_simple_blocker_module_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_simple_blocker_module_init(ngx_conf_t *cf);
static char *ngx_http_simple_blocker(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_simple_blocker_module_commands[] = {

    { ngx_string("blocker_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_simple_blocker,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_simple_blocker_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_simple_blocker_module_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_simple_blocker_module_create_conf,     /* create location configuration */
    ngx_http_simple_blocker_module_merge_conf       /* merge location configuration */
};

ngx_module_t  ngx_http_simple_blocker_module = {
    NGX_MODULE_V1,
    &ngx_http_simple_blocker_module_ctx,     /* module context */
    ngx_http_simple_blocker_module_commands,        /* module directives */
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


static ngx_int_t ngx_http_simple_blocker_module_handler(ngx_http_request_t *r)
{
    ngx_http_simple_blocker_module_conf_t  *arcf;

    arcf = ngx_http_get_module_loc_conf(r, ngx_http_simple_blocker_module);
    
    if (ngx_strncmp(arcf->match.data, (u_char *)"user_agent", arcf->match.len) == 0) {

        if (arcf == NULL || arcf->pattern.len == 0) {
            return NGX_DECLINED;
        }

        if (r->headers_in.user_agent == NULL) {
            return NGX_DECLINED;
        }

        ngx_str_t user_agent_str = r->headers_in.user_agent->value;

        // Log the pattern and user agent for debugging
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "regex pattern: %V", &arcf->pattern);

        ngx_regex_compile_t regex;
        ngx_int_t rc;
        ngx_regex_t *re;

        u_char errstr[NGX_MAX_CONF_ERRSTR];

        ngx_memzero(&regex, sizeof(ngx_regex_compile_t));
        regex.pattern = arcf->pattern;
        regex.pool = r->pool;
        regex.err.len = NGX_MAX_CONF_ERRSTR;
        regex.err.data = errstr;

        rc = ngx_regex_compile(&regex);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "regex compile error: %V", &regex.err);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        re = regex.regex;

        rc = ngx_regex_exec(re, &user_agent_str, NULL, 0);

        if (rc == 0) {
            if (ngx_strncmp(arcf->type.data, "ex", 2) == 0) {
                return 444;
            } else {
                return NGX_OK;
            }
        } else if (rc == NGX_REGEX_NO_MATCHED) {
            // No match found
            if (ngx_strncmp(arcf->type.data, "in", 2) == 0) {
                return 444;
            } else {
                return NGX_OK;
            }
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "regex execution error: %i", rc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    if (ngx_strncmp(arcf->match.data, (u_char *)"cookie", arcf->match.len) == 0)
    {


        ngx_table_elt_t *n;
        ngx_str_t cookie_value = ngx_string("*");
        n = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &arcf->pattern, &cookie_value);
        if (n != NULL) {
            if (ngx_strncmp(arcf->type.data, "ex", 2) == 0) {
                return 444;
            } else {
                return NGX_OK;
            }
        } else {
            if (ngx_strncmp(arcf->type.data, "in", 2) == 0) {
                return 444;
            } else {
                return NGX_OK;
            }
        }


    }

    return NGX_OK;
}

static char * ngx_http_simple_blocker_module_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_simple_blocker_module_conf_t *prev = parent;
    ngx_http_simple_blocker_module_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->pattern, prev->pattern, "");
    ngx_conf_merge_str_value(conf->match, prev->match, "");
    ngx_conf_merge_str_value(conf->type, prev->type, "");

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_simple_blocker_module_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_simple_blocker_module_handler;

    return NGX_OK;
}

static char *ngx_http_simple_blocker(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value;
    ngx_http_simple_blocker_module_conf_t *module_conf;

    module_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_simple_blocker_module);
    value = cf->args->elts;

    // Сохраняем параметры конфигурации
    module_conf->match = value[1];
    module_conf->type = value[2];
    module_conf->pattern = value[3];

    return NGX_CONF_OK;
}

static void *ngx_http_simple_blocker_module_create_conf(ngx_conf_t *cf) {
    ngx_http_simple_blocker_module_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_simple_blocker_module_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}
