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
#include <linux/buffer_head.h>
#include <linux/percpu.h>
#include <linux/percpu_counter.h>
#include <linux/cred.h>
#include <linux/workqueue.h>
#include <linux/cgroup.h>
#include <linux/mbcache.h>
#include <linux/posix_acl.h>
#include <linux/seqlock.h>
#include <linux/dcache.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/cleancache.h>
#include <linux/list_bl.h>
#include <linux/rculist_bl.h>
#include <linux/migrate.h>
#include <linux/migrate_mode.h>
#include <linux/mutex.h>
#include <linux/lglock.h>
#include <asm-generic/bug.h>
#include <linux/completion.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/rwlock.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/blkdev.h>
#include <linux/callback_xxx.h>
// #include <asm-generic/int-l64.h>

struct workqueue_struct;
struct mnt_pcp;

/* 文件系统与内存模块的交互 */
extern void *msg_kmem_cache_alloc(
	struct kmem_cache *s,  
	gfp_t gfpflags, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_kmem_cache_free(
	struct kmem_cache *s, 
	void *x, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_kfree(
	const void *x, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_vfree(
	const void *addr, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void *msg_mempool_alloc(
	mempool_t *pool, 
	gfp_t gfp_mask, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_mempool_free(
	void *element, 
	mempool_t *pool, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct address_space *msg_page_mapping(
	struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern bool msg_list_lru_add(
	struct list_lru *lru, 
	struct list_head *item, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern bool msg_list_lru_del(
	struct list_lru *lru, 
	struct list_head *item, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct page *msg_find_get_page(
	struct address_space *mapping, 
	pgoff_t index, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_mark_page_accessed(
	struct page *, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct page *msg_find_or_create_page(
	struct address_space *mapping, 
	pgoff_t index, gfp_t gfp_mask, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_cancel_dirty_page(
	struct page *page, 
	unsigned int account_size, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void *msg_page_address(
	const struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_bdi_has_dirty_io(
	struct backing_dev_info *bdi, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern unsigned long msg_try_to_free_pages(
	struct zonelist *zonelist, 
	int order, 
	gfp_t gfp_mask, 
	nodemask_t *mask, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_unlock_page(
	struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_account_page_dirtied(
	struct page *page, 
	struct address_space *mapping, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_bdi_wakeup_thread_delayed(
	struct backing_dev_info *bdi, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern char *msg_kstrdup(
	const char *s, 
	gfp_t gfp, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_free_percpu(
	void __percpu *__pdata, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void *msg_kmemdup(
	const void *src, 
	size_t len, 
	gfp_t gfp, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_file_ra_state_init(
	struct file_ra_state *ra, 
	struct address_space *mapping, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_write_one_page(
	struct page *page, 
	int wait, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_truncate_setsize(
	struct inode *inode, 
	loff_t newsize, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_mapping_tagged(
	struct address_space *mapping, 
	int tag, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_do_writepages(
	struct address_space *mapping, 
	struct writeback_control *wbc, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_filemap_fdatawait(
	struct address_space *, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_truncate_inode_pages(
	struct address_space *, 
	loff_t, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_unregister_shrinker(
	struct shrinker *, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_list_lru_destroy(
	struct list_lru *lru, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct kmem_cache *msg_kmem_cache_create(
	const char *name, 
	size_t size, 
	size_t align, 
	unsigned long flags, 
	ctor_func_t ctor, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct page *msg_read_cache_page(
	struct address_space *mapping, 
	pgoff_t index, 
	filler_func_t filler, 
	void *data, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_migrate_page_copy(
	struct page *newpage, 
	struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_migrate_page_move_mapping(
	struct address_space *mapping, 
	struct page *newpage, 
	struct page *page, 
	struct buffer_head *head, 
	enum migrate_mode mode, 
	int extra_count, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_put_page(
	struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_filemap_write_and_wait(
	struct address_space *mapping, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_filemap_flush(
	struct address_space *mapping, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern long msg_get_user_pages(
	struct task_struct *tsk, 
	struct mm_struct *mm, 
	unsigned long start, 
	unsigned long nr_pages, 
	int write, 
	int force, 
	struct page **pages, 
	struct vm_area_struct **vmas, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_register_shrinker(
	struct shrinker *shrinker, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_set_page_dirty(
	struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// include-mm
extern void *msg_kmem_cache_zalloc(
	struct kmem_cache *k, 
	gfp_t flags, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_page_cache_release(
	struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct zoneref *msg_first_zones_zonelist(
	struct zonelist *zonelist, 
	enum zone_type highest_zoneidx, 
	nodemask_t *nodes, 
	struct zone **zone, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct zonelist *msg_node_zonelist(
	int nid, gfp_t flags, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_attach_page_buffers(
	struct page *page, 
	struct buffer_head *head, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct mnt_pcp *msg_alloc_percpu(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct page *msg_read_mapping_page(
	struct address_space *mapping, 
	pgoff_t index, 
	void *data, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_zero_user_segments(
	struct page *page, 
	unsigned start1, 
	unsigned end1, 
	unsigned start2, 
	unsigned end2, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_zero_user(
	struct page *page, 
	unsigned start, 
	unsigned size, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_cleancache_invalidate_fs(
	struct super_block *sb, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在mm/filemap.c中的__lock_page()
extern void msg_lock_page(
	struct page *page, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在mm/slub.c中的__kmalloc()和定义在mm/slub.c中的kmem_cache_alloc_trace()
extern void *msg_kmalloc(
	size_t size, 
	gfp_t flags, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在mm/filemap.c中的find_or_create_page()
extern struct page *msg_grab_cache_page(
	struct address_space *mapping, 
	pgoff_t index, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在mm/slab_common.c中的kmalloc_order_trace()
extern void *msg_kmalloc_large(
	size_t size, 
	gfp_t flags, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在include/linux/slab.h中的kmalloc()
extern void *msg_kzalloc(
	size_t size, 
	gfp_t flags, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);


/* 文件系统与内核模块的交互 */
extern bool msg_capable(
	int cap, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_down_read(
	struct rw_semaphore *sem, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_up_read(
	struct rw_semaphore *sem, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_down_write(
	struct rw_semaphore *sem, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_up_write(
	struct rw_semaphore *sem, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_wake_up_bit(
	void *word, 
	int bit, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern wait_queue_head_t *msg_bit_waitqueue(
	void *word, 
	int bit, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern unsigned long msg_get_seconds(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_put_pid(
	struct pid *pid, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_in_group_p(
	kgid_t, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_yield(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern bool msg_inode_capable(
	const struct inode *inode, 
	int cap, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_task_work_add(
	struct task_struct *task, 
	struct callback_head *twork, 
	bool, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_synchronize_rcu(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_prepare_to_wait(
	wait_queue_head_t *q, 
	wait_queue_t *wait, 
	int state, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_schedule(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_finish_wait(
	wait_queue_head_t *q, 
	wait_queue_t *wait, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct timespec msg_current_fs_time(
	struct super_block *sb, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

/* 
extern int msg_lock_is_held(
	struct lockdep_map *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);
*/

extern void msg_audit_log_link_denied(
	const char *operation, 
	struct path *link, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_send_sig(
	int, 
	struct task_struct *, 
	int, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct timespec msg_timespec_trunc(
	struct timespec t, 
	unsigned gran, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_acct_auto_close_mnt(
	struct vfsmount *m, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg___wait_on_bit(
	wait_queue_head_t *, 
	struct wait_bit_queue *, 
	action_func_t action, 
	unsigned, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_free_uid(
	struct user_struct *, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_module_put(
	struct module *module, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 这个直接在include/linux/fs.h中的i_gid_write()中发送msg_make_kgid()，因为i_gid_write()使用到了文件系统的数据对象，因此不能发送msg_i_gid_write()
extern kgid_t msg_make_kgid(
	struct user_namespace *ns, 
	gid_t gid, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_autoremove_wake_function(
	wait_queue_t *wait, 
	unsigned mode, 
	int sync, 
	void *key, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct timespec msg_current_kernel_time(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_mutex_lock(
	struct mutex *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_mutex_unlock(
	struct mutex *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 这个直接在include/linux/fs.h中的i_gid_write()中发送msg_make_kgid()，因为i_gid_write()使用到了文件系统的数据对象，因此不能发送msg_i_uid_write()
extern kuid_t msg_make_kuid(
	struct user_namespace *ns, 
	uid_t uid, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_io_schedule(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_lg_local_lock_cpu(
	struct lglock *lg, 
	int cpu, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_lg_local_unlock_cpu(
	struct lglock *lg, 
	int cpu, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_warn_slowpath_null(
	const char *file, 
	int line, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 这个直接在include/linux/fs.h中的i_gid_read()中发送msg_from_kgid()，因为i_gid_read()使用到了文件系统的数据对象，因此不能发送msg_i_gid_read()
extern gid_t msg_from_kgid(
	struct user_namespace *targ, 
	kgid_t kgid, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_wake_bit_function(
	wait_queue_t *wait, 
	unsigned mode, 
	int sync, 
	void *arg, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern bool msg_try_module_get(
	struct module *module, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 这个直接在include/linux/fs.h中的i_uid_read()中发送msg_from_kuid()，因为i_uid_read()使用到了文件系统的数据对象，因此不能发送msg_i_uid_read()
extern uid_t msg_from_kuid(
	struct user_namespace *targ, 
	kuid_t kuid, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_destroy_workqueue(
	struct workqueue_struct *wq, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_wait_for_completion(
	struct completion *x, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg___module_get(
	struct module *module, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_call_rcu(
	struct rcu_head *head, 
	func_t func, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_down_read_trylock(
	struct rw_semaphore *sem, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// include-kernel
extern struct filename *msg_audit_reusename(
	const __user char *name, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_audit_getname(
	struct filename *name, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern const struct cred *msg_current_cred(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_percpu_counter_inc(
	struct percpu_counter *fbc, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern const struct cred *msg_get_cred(
	const struct cred *cred, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_percpu_counter_dec(
	struct percpu_counter *fbc, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern kuid_t msg_current_fsuid(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct posix_acl *msg_get_cached_acl_rcu(
	struct inode *inode, 
	int type, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_local_irq_disable(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_local_irq_enable(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_might_sleep(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_preempt_disable(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_preempt_enable(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// bdi_list是全局变量
extern void msg_list_for_each_entry_rcu(
	struct backing_dev_info *bdi, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern bool msg_mod_delayed_work(
	struct workqueue_struct *wq, 
	struct delayed_work *dwork, 
	unsigned long delay, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_css_put(
	struct cgroup_subsys_state *css, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_wake_up_all(
	wait_queue_head_t *q, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_posix_acl_release(
	struct posix_acl *acl, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern unsigned msg_read_seqbegin(
	const seqlock_t *sl, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern bool msg_schedule_delayed_work(
	struct delayed_work *dwork, 
	unsigned long delay, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct dentry *msg_dget(
	struct dentry *dentry, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// d_hash是member，直接在内部使用即可
extern void msg_hlist_bl_for_each_entry_rcu(
	struct dentry *dentry, 
	struct hlist_bl_node *node, 
	struct hlist_bl_head *b, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct hlist_bl_node *msg_hlist_bl_first_rcu(
	struct hlist_bl_head *h, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct hlist_bl_node *msg_rcu_dereference_raw(
	struct hlist_bl_node *pos, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// d_lru是member，直接在内部使用即可
extern struct dentry *msg_list_entry_rcu(
	struct list_head *list, 
	struct dentry *dentry, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_cond_resched(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_wake_up_interruptible(
	struct __wait_queue_head *ppoll, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_seqcount_init(
	seqcount_t *s, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

/* 
extern void msg_lockdep_set_class(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);
*/

extern void msg_mutex_init(
	struct mutex *mutex, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_wait_event(
	struct __wait_queue_head wq, 
	bool condition, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_percpu_counter_add(
	struct percpu_counter *fbc, 
	s64 amount, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern const struct file_operations *msg_fops_get(
	const struct file_operations *fops, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_init_waitqueue_head(
	struct __wait_queue_head *q, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_wake_up(
	struct __wait_queue_head *q, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern int msg_wait_event_interruptible_timeout(
	struct __wait_queue_head wq, 
	bool condition, 
	unsigned long timeout, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_audit_inode(
	struct filename *name, 
	const struct dentry *dentry, 
	unsigned int parent, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_audit_inode_child(
	const struct inode *parent, 
	const struct dentry *dentry, 
	const unsigned char type, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern struct hlist_node *msg_srcu_dereference(
	struct hlist_node *p, 
	struct srcu_struct *sp, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// rcu_header是member，直接在内部使用
extern void msg_kfree_rcu(
	struct super_block *s, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_lock()
extern void msg_write_lock(
	rwlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/locking/rwsem-spinlock.c中的__init_rwsem()
extern void msg_init_rwsem(
	struct rw_semaphore *sem, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/workqueue.c中的queue_delayed_work_on()
extern bool msg_queue_delayed_work(
	struct workqueue_struct *wq, 
	struct delayed_work *dwork, 
	unsigned long delay, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock()
extern void msg_spin_lock(
	spinlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock()
extern void msg_spin_unlock(
	spinlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock_irq()
extern void msg_spin_lock_irq(
	spinlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_irq()
extern void msg_spin_unlock_irq(
	spinlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_trylock()
extern void msg_spin_trylock(
	spinlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/panic.c中的warn_slowpath_null()
extern void msg_WARN_ON(
	bool condition, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/printk/printk.c中的__printk_ratelimit()
extern int msg_printk_ratelimit(
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/sched/wait.c中的out_of_line_wait_on_bit_lock()
extern int msg_wait_on_bit_lock(
	void *word, 
	int bit, 
	action_func_t action, 
	unsigned mode, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_lock_irq()
extern void msg_write_lock_irq(
	rwlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_unlock_irq()
extern void msg_write_unlock_irq(
	rwlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_read_lock()
extern void msg_read_lock(
	rwlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_read_unlock()
extern void msg_read_unlock(
	rwlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_irqrestore()
extern void msg_spin_unlock_irqrestore(
	spinlock_t *lock, 
	unsigned long flags, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/workqueue.c中的queue_work_on()
extern bool msg_queue_work(
	struct workqueue_struct *wq, 
	struct work_struct *work, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock_bh()
extern void msg_spin_lock_bh(
	spinlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_bh()
extern void msg_spin_unlock_bh(
	spinlock_t *lock, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);



/* 文件系统与通用块层的交互 */
extern void msg_bdevname(
	struct block_device *bdev, 
	char *buf, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_submit_bio(
	int rw, 
	struct bio *bio, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_put_io_context(
	struct io_context *ioc, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_blk_finish_plug(
	struct blk_plug *plug, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

extern void msg_blk_start_plug(
	struct blk_plug *plug, 
	int msqid_from_fs_to_kernel, 
	int msqid_from_kernel_to_fs
);

#endif
