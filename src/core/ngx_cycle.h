
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    void                  ****conf_ctx;  /* 配置文件，保存了每个模块的配置信息 */
    ngx_pool_t               *pool;  /* 内存池指针 */

    ngx_log_t                *log;  /* 日志 */
    ngx_log_t                 new_log;  // TODO new_log 指什么？

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;  /* 连接文件句柄数组 */
    ngx_connection_t         *free_connections;  /* 空闲连接 */
    ngx_uint_t                free_connection_n;  /* 空闲连接个数 */

    ngx_module_t            **modules;  /* 模块数组 */
    ngx_uint_t                modules_n;  /* 模块个数 */
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue;  /* 可重用的连接队列 */
    ngx_uint_t                reusable_connections_n;  /* 可重用的连接数 */

    ngx_array_t               listening;  /* 监听的 socket 端口数组 */
    ngx_array_t               paths;  /* TODO 什么 path？ */

    ngx_array_t               config_dump;  /* TODO config_dump 指的是什么？ dump 的含义是什么？ */
    ngx_rbtree_t              config_dump_rbtree;  /* TODO rbtree 是什么？为什么要构造 rbtree 来表示 config_dump？ */
    ngx_rbtree_node_t         config_dump_sentinel;  /* TODO sentinel 在 rbtree 中有什么含义？ */

    ngx_list_t                open_files;  /* 打开的文件 */
    ngx_list_t                shared_memory;  /* 共享内存的链表 */

    ngx_uint_t                connection_n;  /* 当前连接的个数 */
    ngx_uint_t                files_n;  /* 打开的文件个数 */

    ngx_connection_t         *connections;  /* 连接数组 */
    ngx_event_t              *read_events;  /* 读取事件 */
    ngx_event_t              *write_events; /* 写入事件 */

    ngx_cycle_t              *old_cycle;  /* TODO old_cycle 的作用是什么？与 old 相对，当前的 cycle 是 new_cycle 吗？如果是，new 在什么地方呢？*/

    ngx_str_t                 conf_file;  /* 配置文件的路径 */
    ngx_str_t                 conf_param;  /* 配置参数 */
    ngx_str_t                 conf_prefix;  /* 配置文件的所在路径 */
    ngx_str_t                 prefix;  /* nginx 的工作路径 */
    ngx_str_t                 lock_file;  /* 锁文件的路径 */
    ngx_str_t                 hostname;  /* 主机名称 */
};


typedef struct {
    ngx_flag_t                daemon;  /* TODO daemon? */
    ngx_flag_t                master;

    ngx_msec_t                timer_resolution;  /* TODO time_resolution? ngx_msec_t 是什么类型？ */
    ngx_msec_t                shutdown_timeout;

    ngx_int_t                 worker_processes;
    ngx_int_t                 debug_points;  /* TODO */

    ngx_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;  /* TODO priority? */

    ngx_uint_t                cpu_affinity_auto;  /* TODO cpu_affinity_auto? */
    ngx_uint_t                cpu_affinity_n;  /* TODO cpu_affinity_n? */
    ngx_cpuset_t             *cpu_affinity;  /* TODO cpu_affinity? */

    char                     *username;
    ngx_uid_t                 user;
    ngx_gid_t                 group;

    ngx_str_t                 working_directory;
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;
    ngx_str_t                 oldpid;  /* TODO oldpid 是做什么用的？ */

    ngx_array_t               env;
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
