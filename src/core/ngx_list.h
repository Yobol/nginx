
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

// 使用链表 + 数组的组合设计，有几点好处：
// 1. 链表中存储的元素可以是任何一种类型，比较灵活；
// 2. 小块的内存使用链表访问效率是低下的，使用数组通过偏移量来直接访问内存则要高效得多

// 声明 ngx_list_part_t 是 struct ngx_list_part_s 类型
typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {  // 声明链表元素的结构体
    void             *elts;  // 表示链表元素中的数组，指向数组的起始地址
    ngx_uint_t        nelts;  // 表示数组的容量
    ngx_list_part_t  *next;  // 指向该元素在链表中下一个元素在内存中的首地址
};


typedef struct {
    ngx_list_part_t  *last; // 链表的最后一个元素
    ngx_list_part_t   part; // 链表首元素
    // TODO 为什么没有链表的长度？？
    size_t            size; // 不是链表长度，而是链表中每个数组元素的容量
    // 链表中的数组元素一旦分配后是不可更改的
    ngx_uint_t        nalloc;  // 不是链表长度，而是链表中每个数组的容量
    ngx_pool_t       *pool;  // 链表中管理内存分配的内存池对象，用于分配内存
} ngx_list_t;  // Nginx 封装的链表容器，HTTP 的请求头部就是使用 ngx_list_t 来存储的
// ngx_list_t 描述整个链表，而 ngx_list_part_t 只描述链表中的一个元素（每个 ngx_list_part_t 都是一个数组）
// 如果一个链表中的所有元素都是由一个 pool 内存池分配的话，该链表的所有数据都将是连续的 => 每个数组的 elts

// pool 参数是内存池对象，用于为链表分配内存空间
// n 参数是链表中每个数组的容量
// size 参数是链表中每个数组元素的容量
// 返回新创建的链表地址，如果创建失败，则返回 NULL 空指针
// 新创建的链表会包含一个链表元素，即链表中的 part 成员
// use case:
// ngx_list_t *testlist = ngx_list_create(r->pool, 4, sizeof(ngx_str_t));
// if ngx_list_t == NULL {
//     return NGX_ERROR;
// }
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

// 和 ngx_list_create 功能类似， 只是 init 方法是在链表创建成功后调用
// 创建成功返回 NGX_OK(0)，失败返回 NGX_ERROR(-1)
static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size); // 初始化首元素：分配内存空间
    if (list->part.elts == NULL) {  // 分配内存空间失败
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  ngx_list_part_t *part = &list.part;
 *  ngx_str_t *data = part->elts;
 *
 *  // i 表示元素在链表的每个 ngx_list_part_t 数组中的序号
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              // 如果某个 ngx_list_part_t 数组的 next 指针为空
 *              // 则说明已经遍历完链表
 *              break;
 *          }
 *
 *          // 访问下一个 ngx_list_part_t
 *          part = part->next;
 *          data = part->elts;
 *          // 将 i 置为0，准备访问下一个链表元素
 *          i = 0;
 *      }
 *
 *      //...  data[i] ...
 *      printf("list element: %*s\n", str[i].len, str[i].data);
 *  }
 */

// 添加新的链表元素
// 正常情况下，返回的是新分配的元素的首地址
// 添加失败会返回 NULL 空指针
// use case:
// ngx_str_t *str = ngx_list_push(testlist)
// if (str == NULL) {
//     return NGX_ERROR;
// }
// str->len = sizeof("Hello world");
// str->data = "Hello world"
void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
