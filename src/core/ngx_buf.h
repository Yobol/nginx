
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

// 缓冲区 ngx_buf_t 是 Nginx 处理大数据的关键数据结构，它既应用于内存数据也应用于磁盘数据
typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos;  // 本次处理的（内存）起始位置
    u_char          *last;  // 本次处理的（内存）终止位置（不包含 last）
    off_t            file_pos;  // 本次处理的文件起始位置
    off_t            file_last;  // 本次处理的文件终止位置（TODO 是否包含 file_last)

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    ngx_buf_tag_t    tag;  // 表示当前缓冲区的类型，由哪个模块使用就指向这个模块 ngx_module_t 变量的地址
    ngx_file_t      *file; // 引用的文件
    // 当前缓冲区的影子缓冲区，该字段很少使用到
    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1;  // 临时内存标志位，为1时表示数据在内存中且这段内存可以被修改

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;  // 标志位，为1时表示数据在内存中且这段内存不可以被修改

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;  // 标志位，为1时表示这段内存时用 mmap 系统调用映射过来的，这段内存不可以被修改

    unsigned         recycled:1;  // 标志位，为1时表示这段内存可以被回收
    unsigned         in_file:1;  // 标志位，为1时表示这段缓冲区处理的是文件而非内存
    unsigned         flush:1;  // 标志位，为1时表示需要执行 flush 操作
    unsigned         sync:1;  // 标志位，为1时表示操作该缓冲区时使用同步方式，该方式可能会阻塞 Nginx 进程
    unsigned         last_buf:1;  // 标志位，为1时表示当前缓冲区是最后一块缓冲区（ngx_buf_t 可以由 ngx_chain_t 链表串联起来）
    unsigned         last_in_chain:1;  // 标志位，为1时表示当前缓冲区是 ngx_chain_t 中的最后一块缓冲区

    unsigned         last_shadow:1;  // 标志位，为1时表示是最后一个影子缓冲区，与 shadow 字段配合使用
    unsigned         temp_file:1;  // 标志位，为1时表示当前缓冲区属于临时文件

    /* STUB */ int   num;
};
// ngx_buf_t 是一种基本数据结构，本质上它提供的仅仅是一些指针成员和标志位。
// 对于 HTTP 模块来说，需要注意 HTTP 框架、事件框架是如何设置和使用 pos、last 等指针以及如何处理这些标志位的。
// 如果我们自定义一个 ngx_buf_t 结构体，不应当受限于上述用法，而应该根据业务需求自行定义。
// 例如，当用一个 ngx_buf_t 缓冲区转发上下游 TCP 流时，
// pos 会指向将要发送到下游的 TCP 流起始地址，而 last 会指向预备接收上游 TCP 流的缓冲区起始地址。


// ngx_chain_s 结构体用来对分配的内存进行统一管理，减少代码中出现内存泄漏的可能性
struct ngx_chain_s {
    ngx_buf_t    *buf;  // ngx_buf_t 缓冲区
    ngx_chain_t  *next;  // 指向下一个 ngx_chain_t 元素，如果当前 ngx_buf_t->last_in_chain 为1，则该字段应置为 NULL
    // 在向用户发送 HTTP 包体时，就要传入 ngx_chain_t 链表对象。
    // 注意，如果是最后一个 ngx_chain_t ，那么必须将 next 置为 NULL，
    // 否则永远不会发送成功，而且这个请求将一直不会结束（Nginx 框架的要求）。
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
