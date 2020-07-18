
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_429)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    ngx_uint_t                       status;
    ngx_msec_t                       response_time;
    ngx_msec_t                       connect_time;
    ngx_msec_t                       header_time;
    ngx_msec_t                       queue_time;
    off_t                            response_length;
    off_t                            bytes_received;
    off_t                            bytes_sent;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;
    ngx_uint_t                       down;

    unsigned                         backup:1;

    NGX_COMPAT_BEGIN(6)
    NGX_COMPAT_END
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020
#define NGX_HTTP_UPSTREAM_MAX_CONNS     0x0100


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_http_upstream_local_t;


typedef struct {
    /*
     * 只有当 ngx_http_upstream_t 结构体中没有实现 resolved 成员时， 这个 upstream 才会生效
     * 用于定义上游服务器的配置
     */
    ngx_http_upstream_srv_conf_t    *upstream;

    ngx_msec_t                       connect_timeout;  // 建立 TCP 连接的超时时间
    /*
     * 发送 TCP 请求的超时时间， 实际上就是写事件添加到定时器中设置的超时时间
     */
    ngx_msec_t                       send_timeout;
    /*
     * 接收 TCP 响应的超时时间，实际上就是读事件添加到定时器中设置的超时时间
     */
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       next_upstream_timeout;

    // TCP 的 SO_SNOLOWAT 选项，表示发送缓冲区的下限
    size_t                           send_lowat;
    /*
     * 定义了 ngx_http_upstream_t 中 buffer 缓冲区的内存大小
     */
    size_t                           buffer_size;
    size_t                           limit_rate;

    /*
     * 仅当 buffering 标识位为 1 并且向下游转发响应时生效
     * 会设置到 ngx_event_pipe_t 结构体的 busy_size 成员中
     */
    size_t                           busy_buffers_size;
    /*
     * 在 buffering 标识位为 1 时，如果上游速度快于下游速度，将有可能把来自上游的响应存储到磁盘上的临时文件中，
     * 而 max_temp_file_size 指定了该临时文件的最大长度，
     * 实际上，它讲限制 ngx_event_pipe_t 结构体中的 temp_file
     */
    size_t                           max_temp_file_size;
    // 表示将缓冲区中的响应写入临时文件时一次写入字符流的最大长度
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    // 以缓存响应的方式转发上游服务器的包体时所使用的内存大小
    ngx_bufs_t                       bufs;

    /*
     * 在转发请求时可以忽略的头部字段
     * 该字段最多可以屏蔽 32 个头部字段
     *
     * 该版本中 upstream 机制只使用了 9 个位用于忽略头部的处理
     * #define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
     * #define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
     * #define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
     * #define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
     * #define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
     * #define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
     * #define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
     * #define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
     * #define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200
     */
    ngx_uint_t                       ignore_headers;
    /*
     * 以二进制位来标识一些错误码
     * 如果处理上游响应时接收到这些错误码，则不会将响应转发给下游客户端，而是选择下一个上游服务器来重发请求
     */
    ngx_uint_t                       next_upstream;
    /*
     * 当响应存放到临时文件时，该字段表示所创建的目录和文件的访问权限
     */
    ngx_uint_t                       store_access;
    ngx_uint_t                       next_upstream_tries;
    /*
     * buffering 为 1 时表示打开缓存，这时认为上游的网速快于下游的网速，会尽量在内存或磁盘中缓存来自上游的响应
     * buffering 为 0 时只会开辟一块固定大小的内存块作为缓存来转发响应
     */
    ngx_flag_t                       buffering;
    ngx_flag_t                       request_buffering;
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

    /*
     * 取值为 1 时，表示与上游服务器交互时将不检查 Nginx 与下游客户端间的连接是否断开
     */
    ngx_flag_t                       ignore_client_abort;
    /*
     * 当解析上游响应的包头时，如果解析后设置到 header_in 结构体中的 status_n 错误码大于 400，
     * 则会试图把它与 error_page 中指定的错误码相匹配，如果匹配上，则发送 error_page 中指定的响应，
     * 否则继续返回上游服务器的错误码
     */
    ngx_flag_t                       intercept_errors;
    /*
     * buffering 标识位为 1 的情况下转发响应时才有意义。
     * 这时，如果 cyclic_temp_file 为 1，则会试图服用临时文件中已经使用过的空间
     *
     * 不建议讲 cyclic_temp_file 设为 1
     */
    ngx_flag_t                       cyclic_temp_file;
    ngx_flag_t                       force_ranges;

    // 当 buffering 标识位 为 1 的情况下转发响应时，存放临时文件的路径
    ngx_path_t                      *temp_path;

    /*
     * 不转发的头部。实际上是通过 ngx_http_upstream_hide_headers_hash 方法，
     * 根据 hide_headers 和 pass_headers 动态数组构造出的需要隐藏的 HTTP 头部散列表
     */
    ngx_hash_t                       hide_headers_hash;
    ngx_array_t                     *hide_headers;  // 不希望转发给下游客户端的响应头部
    /*
     * 当转发上游响应头部（ngx_http_upstream_t 中 headers_in 结构体中的头部）给下游客户端时，
     * upstream 机制默认不会转发如 Date, Server 之类的头部，
     * 如果确实需要直接转发它们到下游，就设置到 pass_headers 动态数组中
     */
    ngx_array_t                     *pass_headers;

    ngx_http_upstream_local_t       *local;  // 连接上游服务器时使用的本机地址
    ngx_flag_t                       socket_keepalive;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache_zone;
    ngx_http_complex_value_t        *cache_value;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    off_t                            cache_max_range_offset;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;
    ngx_msec_t                       cache_lock_age;

    ngx_flag_t                       cache_revalidate;
    ngx_flag_t                       cache_convert_head;
    ngx_flag_t                       cache_background_update;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *cache_purge;
    ngx_array_t                     *no_cache;
#endif

    /*
     * 当 ngx_http_upstream_t 中的 store 标识位为 1 时，如果需要将上游的响应存放到文件中，
     * store_lengths 表示存放路径的长度；
     * store_values 表示存放的路径
     */
    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

#if (NGX_HTTP_CACHE)
    signed                           cache:2;
#endif
    // 和 ngx_http_upstream_t 中的 store 相同，仍只有 0 和 1 被使用到
    signed                           store:2;
    /*
     * 当取值为 1 时，如果上游返回 404 则会直接转发这个响应码给下游，而不会去与 error_page 进行比较
     */
    unsigned                         intercept_404:1;
    /*
     * 当取值为 1 时，将会根据 ngx_http_upstream_t 中 headers_in 结构体中的 X-Accel-Buffering 头部（取值 yes 或 no）
     * 来改变 buffering 标识位，当其值为 yes 时，buffering 标识位为 1
     *
     * 因此 change_buffering 为 1 时，将有可能根据上游服务器返回的响应头部，动态地决定是以上游网速优先，还是以下游网速优先
     */
    unsigned                         change_buffering:1;
    unsigned                         pass_trailers:1;
    unsigned                         preserve_output:1;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;

    ngx_http_complex_value_t        *ssl_name;
    ngx_flag_t                       ssl_server_name;
    ngx_flag_t                       ssl_verify;
#endif

    ngx_str_t                        module;  // 使用的 upstream 的模块名称，进用于记录日志

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;
    ngx_list_t                       trailers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                        name;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    ngx_http_upstream_handler_pt     read_event_handler;  // 处理读事件的回调方法，每一个阶段都有不同的 read_event_handler
    ngx_http_upstream_handler_pt     write_event_handler;  // 处理写事件的回调方法，每一个阶段都有不同的 write_event_handler

    ngx_peer_connection_t            peer;  // 表示主动向上游服务器发起的连接

    // 当向下游客户端转发响应时（ngx_http_request_t 结构体中的 subrequest_in_memory 标识位为 0），
    // 如果打开了缓存则认为上游网速更快（conf 配置中的 buffering 为 1），
    // 这时会使用 pipe 成员来转发响应。
    // 在使用这种方式转发响应时，必须由　HTTP 模块在使用　upstream 机制钱构造　pipe 结构体，否则会出现严重的　coredump 错误
    ngx_event_pipe_t                *pipe;

    ngx_chain_t                     *request_bufs;  // 决定向上游服务器发送的请求包体

    // 定义了向下游发送响应的方式
    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    ngx_http_upstream_conf_t        *conf;  // 使用 upstream 机制时的各种配置
    ngx_http_upstream_srv_conf_t    *upstream;
#if (NGX_HTTP_CACHE)
    ngx_array_t                     *caches;
#endif

    /*
     * HTTP 模块在实现　process_header 方法时，如果希望 upstream 直接转发响应，
     * 就需要把解析出的响应头部适配为 HTTP 的响应头部，同时需要将包头中的信息设置到 headers_in 结构体中
     */
    ngx_http_upstream_headers_in_t   headers_in;

    ngx_http_upstream_resolved_t    *resolved;  // 指定上游服务器的地址，用于解析主机域名

    ngx_buf_t                        from_client;

    // buffer 在处理 HTTP 请求的过程中可以被复用：
    // 1. 回调 process_header 方法解析上游响应的头部时，buffer 会存储完整的头部信息
    // 2. 当 conf.buffering 为 1 时，表示 upstream 会使用多个缓冲区或磁盘文件向下游转发上游的包体，buffer 没有意义
    // 3. 当 conf.buffering 为 0 时，只是用 buffer 缓冲区用于反复接收上游的包体，进而向上游转发
    // 4. 当 upstream 并不用于转发上游包体时，buffer 会被用于返回接受上游的包体
    ngx_buf_t                        buffer;  // 存储上游服务器返回的响应内容
    off_t                            length;  // 表示来自上游服务器的响应包体的长度

    /*
     * out_bufs 在两种场景下有不同的意义：
     *
     * 1. 当不需要转发响应包体，且使用默认的 input_filter 方法（ngx_http_upstream_non_buffered_filter 方法）处理包体时，
     *    out_bufs 将会指向响应包体，事实上，out_bufs 链表中会产生多个 ngx_buf_t 缓冲区，每个缓冲区都指向 buffer 缓存的一部分
     *    这里的一部分就是每次调用 recv 方法接收到的一段 TCP 流
     *
     * 2. 当需要转发响应包体到下游时（conf.buffering 标识位为 0，即以下游网速优先），这个链表指向上一次向下游转发响应到现在这段时间内接收自上游的缓存响应
     */
    ngx_chain_t                     *out_bufs;

    /*
     * 当需要转发响应包体到下游时，表示上一次向下游转发响应时没有发送完的内容
     */
    ngx_chain_t                     *busy_bufs;
    /*
     * 用于回收 out_bufs 中已经发送给下游的 ngx_buf_t 结构体
     */
    ngx_chain_t                     *free_bufs;

    /*
     * 处理响应包体前的初始化方法，其中 data 参数用于传递用户数据结构，实际上就是下面的 input_filter_ctx 指针
     */
    ngx_int_t                      (*input_filter_init)(void *data);
    /*
     * 处理响应包体的方法，其中 data 参数用于传递用户数据结构，而 bytes 表示本次接收到的包体长度
     * 返回 NGX_ERROR 时表示处理包体错误，请求需要结束，否则都将继续 upstream 流程
     */
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    // 用于传递 HTTP 模块自定义的数据结构，在 input_filter_init 和 input_filter 被回调时会作为参数传递过去
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);  // 必须实现：用于构造发往上游服务器的请求
    // 与上游服务器通信失败时，如果按照重试规则还需要再次向上游服务器发送连接，则会调用 reinit_request 方法
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
    /*
     * 必须实现： 当接收到上游服务器的响应后会调用该方法，解析上游服务器返回响应的包头
     * - 返回 NGX_AGAIN 则表示响应包头还没有接收完，需要再次调用 process_header 方法接收响应
     * - 返回 NGX_HTTP_UPSTREAM_INVALID_HEADER 表示包头不合法
     * - 返回 NGX_ERROR 表示出现错误
     * - 返回 NGX_OK 表示解析到完整的包头
     */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    void                           (*abort_request)(ngx_http_request_t *r);
    // 必须实现：当请求结束后会被调用，用于销毁 upstream
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
    /*
     * 在上游返回的响应出现 Location 或 Refresh 头部表示重定向时，
     * 会通过 ngx_http_upstream_process_headers 方法调用到可由 HTTP 模块实现的 rewrite_redirect 方法
     */
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       start_time;

    ngx_http_upstream_state_t       *state;  // 用于表示上游响应的错误码、包体长度等信息

    ngx_str_t                        method;  // 只在使用文件缓存时有意义
    // schema 和 uri 只在记录日志时会用到
    ngx_str_t                        schema;
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        ssl_name;
#endif

    ngx_http_cleanup_pt             *cleanup;  // 用于表示是否需要清理资源

    unsigned                         store:1;  // 是否指定文件缓存路径的标识位
    unsigned                         cacheable:1;  // 是否启用文件缓存
    unsigned                         accel:1;
    unsigned                         ssl:1;  // 是否基于 SSL 协议访问上游服务器
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1;  // 是否使用多个 buffer 以及磁盘文件缓冲上游服务器的响应
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;

    /*
     * request_sent 表示是否已经向上游服务器发送了请求：
     *
     * - 当 request_sent 取值为 1 时，表示 upstream 机制已经向上游服务器发送了全部或部分的请求
     */
    unsigned                         request_sent:1;
    unsigned                         request_body_sent:1;
    unsigned                         request_body_blocked:1;
    /*
     * 如果不转发响应到客户端，则 header_sent 没有意义；
     * 如果把响应直接转发给客户端， header_sent 标识位表示包头是否发送，取值为 1 时表示已经把包头转发给客户端了
     */
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


// r->upstream 在初始状态下为 NULL，需要调用 ngx_http_upstream_create 方法创建 upstream
ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);  // 为请求创建 upstream
// 启动之前执行 设置上游服务器地址 和 设置 upstream 的回调方法
void ngx_http_upstream_init(ngx_http_request_t *r);  // 启动 upstream
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
