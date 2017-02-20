#ifndef __LINUX_CALLBACK_XXX_H
#define __LINUX_CALLBACK_XXX_H

#include <linux/my_msg.h>
#include <linux/my_msg.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mempool.h>
#include <linux/mm.h>
#include <linux/list_lru.h>
#include <linux/capability.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include <linux/time.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/iocontext.h>
#include <linux/interactive_design.h>


/* 文件系统与内存模块的交互 */
extern void callback_kmem_cache_alloc(struct my_msgbuf *this);
extern void callback_kmem_cache_free(struct my_msgbuf *this);
extern void callback_kfree(struct my_msgbuf *this);
extern void callback_vfree(struct my_msgbuf *this);
extern void callback_mempool_alloc(struct my_msgbuf *this);
extern void callback_mempool_free(struct my_msgbuf *this);
extern void callback_page_mapping(struct my_msgbuf *this);
extern void callback_list_lru_add(struct my_msgbuf *this);
extern void callback_list_lru_del(struct my_msgbuf *this);


/* 文件系统与内核模块的交互 */
extern void callback_capable(struct my_msgbuf *this);
extern void callback_down_read(struct my_msgbuf *this);
extern void callback_up_read(struct my_msgbuf *this);
extern void callback_down_write(struct my_msgbuf *this);
extern void callback_up_write(struct my_msgbuf *this);
extern void callback_wake_up_bit(struct my_msgbuf *this);
extern void callback_bit_waitqueue(struct my_msgbuf *this);
extern void callback_get_seconds(struct my_msgbuf *this);
extern void callback_put_pid(struct my_msgbuf *this);


/* 文件系统与通用块层的交互 */
extern void callback_bdevname(struct my_msgbuf *this);
extern void callback_submit_bio(struct my_msgbuf *this);
extern void callback_put_io_context(struct my_msgbuf *this);

#endif
