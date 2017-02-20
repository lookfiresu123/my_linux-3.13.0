#ifndef __LINUX_MSG_XXX_H
#define __LINUX_MSG_XXX_H

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/mempool.h>
#include <linux/mm_types.h>
#include <linux/list_lru.h>
#include <linux/rwsem.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/blk_types.h>
#include <linux/iocontext.h>

/* 文件系统与内存模块的交互 */
extern void *msg_kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_kmem_cache_free(struct kmem_cache *s, void *x, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_kfree(const void *x, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_vfree(const void *addr, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void *msg_mempool_alloc(mempool_t *pool, gfp_t gfp_mask, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_mempool_free(void *element, mempool_t *pool, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern struct address_space *msg_page_mapping(struct page *page, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern bool msg_list_lru_add(struct list_lru *lru, struct list_head *item, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern bool msg_list_lru_del(struct list_lru *lru, struct list_head *item, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);


/* 文件系统与内核模块的交互 */
extern bool msg_capable(int cap, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_down_read(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_up_read(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_down_write(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_up_write(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_wake_up_bit(void *word, int bit, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern wait_queue_head_t *msg_bit_waitqueue(void *word, int bit, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern unsigned long msg_get_seconds(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_put_pid(struct pid *pid, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);


/* 文件系统与通用块层的交互 */
extern void msg_bdevname(struct block_device *bdev, char *buf, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_submit_bio(int rw, struct bio *bio, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_put_io_context(struct io_context *ioc, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);

#endif
