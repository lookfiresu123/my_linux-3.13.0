#ifndef __LINUX_MSG_XXX_H
#define __LINUX_MSG_XXX_H

#include <linux/lockdep.h>
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
#include <linux/mm_types.h>
#include <linux/backing-dev.h>
#include <linux/mmzone.h>
#include <linux/nodemask.h>
#include <linux/compiler.h>
#include <linux/writeback.h>
#include <linux/shrinker.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/wait.h>
// #include <linux/lockdep.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <uapi/linux/time.h>
#include <linux/mount.h>
#include <linux/module.h>

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
extern struct page *msg_find_get_page(struct address_space *mapping, pgoff_t index, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_mark_page_accessed(struct page *, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern struct page *msg_find_or_create_page(struct address_space *mapping, pgoff_t index, gfp_t gfp_mask, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_cancel_dirty_page(struct page *page, unsigned int account_size, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void *msg_page_address(const struct page *page, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg_bdi_has_dirty_io(struct backing_dev_info *bdi, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern unsigned long msg_try_to_free_pages(struct zonelist *zonelist, int order, gfp_t gfp_mask, nodemask_t *mask, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_unlock_page(struct page *page, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_account_page_dirtied(struct page *page, struct address_space *mapping, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_bdi_wakeup_thread_delayed(struct backing_dev_info *bdi, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern char *msg_kstrdup(const char *s, gfp_t gfp, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_free_percpu(void __percpu *__pdata, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void *msg_kmemdup(const void *src, size_t len, gfp_t gfp, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg_write_one_page(struct page *page, int wait, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_truncate_setsize(struct inode *inode, loff_t newsize, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg_mapping_tagged(struct address_space *mapping, int tag, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg_do_writepages(struct address_space *mapping, struct writeback_control *wbc, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg_filemap_fdatawait(struct address_space *, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_truncate_inode_pages(struct address_space *, loff_t, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_unregister_shrinker(struct shrinker *, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_list_lru_destroy(struct list_lru *lru, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);


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
extern int msg_in_group_p(kgid_t, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_yield(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern bool msg_inode_capable(const struct inode *inode, int cap, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg_task_work_add(struct task_struct *task, struct callback_head *twork, bool, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_synchronize_rcu(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_schedule(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_finish_wait(wait_queue_head_t *q, wait_queue_t *wait, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern struct timespec msg_current_fs_time(struct super_block *sb, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
// extern int msg_lock_is_held(struct lockdep_map *lock, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_audit_log_link_denied(const char *operation, struct path *link, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg_send_sig(int, struct task_struct *, int, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern struct timespec msg_timespec_trunc(struct timespec t, unsigned gran, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_acct_auto_close_mnt(struct vfsmount *m, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern int msg___wait_on_bit(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_free_uid(struct user_struct *, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_module_put(struct module *module, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);



/* 文件系统与通用块层的交互 */
extern void msg_bdevname(struct block_device *bdev, char *buf, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_submit_bio(int rw, struct bio *bio, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);
extern void msg_put_io_context(struct io_context *ioc, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs);

#endif
