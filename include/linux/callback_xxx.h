#ifndef __LINUX_CALLBACK_XXX_H
#define __LINUX_CALLBACK_XXX_H

#include <linux/lockdep.h>
//#include <linux/my_msg.h>
// #include <linux/my_msg.h>
#include <linux/msgA.h>
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
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/page-flags.h>
#include <linux/backing-dev.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <linux/writeback.h>
#include <linux/shrinker.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/task_work.h>
#include <linux/rcupdate.h>
// #include <linux/lockdep.h>
#include <linux/audit.h>
#include <linux/acct.h>
#include <linux/module.h>
#include <linux/list_bl.h>
#include <linux/interactive_design.h>

typedef struct hlist_bl_head *(*d_hash_t)(const struct dentry *, unsigned int);
typedef void (*ctor_func_t)(void *);
typedef int (*filler_func_t)(void *, struct page *);
typedef void (*func_t)(struct rcu_head *rcu);
typedef int (*action_func_t)(void *);

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
extern void callback_find_get_page(struct my_msgbuf *this);
extern void callback_mark_page_accessed(struct my_msgbuf *this);
extern void callback_find_or_create_page(struct my_msgbuf *this);
extern void callback_cancel_dirty_page(struct my_msgbuf *this);
extern void callback_page_address(struct my_msgbuf *this);
extern void callback_bdi_has_dirty_io(struct my_msgbuf *this);
extern void callback_try_to_free_pages(struct my_msgbuf *this);
extern void callback_unlock_page(struct my_msgbuf *this);
extern void callback_account_page_dirtied(struct my_msgbuf *this);
extern void callback_bdi_wakeup_thread_delayed(struct my_msgbuf *this);
extern void callback_kstrdup(struct my_msgbuf *this);
extern void callback_free_percpu(struct my_msgbuf *this);
extern void callback_kmemdup(struct my_msgbuf *this);
extern void callback_file_ra_state_init(struct my_msgbuf *this);
extern void callback_write_one_page(struct my_msgbuf *this);
extern void callback_truncate_setsize(struct my_msgbuf *this);
extern void callback_mapping_tagged(struct my_msgbuf *this);
extern void callback_do_writepages(struct my_msgbuf *this);
extern void callback_filemap_fdatawait(struct my_msgbuf *this);
extern void callback_truncate_inode_pages(struct my_msgbuf *this);
extern void callback_unregister_shrinker(struct my_msgbuf *this);
extern void callback_list_lru_destroy(struct my_msgbuf *this);
extern void callback_kmem_cache_create(struct my_msgbuf *this);
extern void callback_read_cache_page(struct my_msgbuf *this);
extern void callback_migrate_page_copy(struct my_msgbuf *this);
extern void callback_migrate_page_move_mapping(struct my_msgbuf *this);
extern void callback_put_page(struct my_msgbuf *this);
extern void callback_filemap_write_and_wait(struct my_msgbuf *this);
extern void callback_filemap_flush(struct my_msgbuf *this);
extern void callback_get_user_pages(struct my_msgbuf *this);
extern void callback_register_shrinker(struct my_msgbuf *this);
extern void callback_set_page_dirty(struct my_msgbuf *this);

// include-mm
extern void callback_kmem_cache_zalloc(struct my_msgbuf *this);
extern void callback_page_cache_release(struct my_msgbuf *this);// 宏 -> put_page
extern void callback_first_zones_zonelist(struct my_msgbuf *this);// 调用了定义在mm/mmzone.c中的next_zones_zonelist
extern void callback_node_zonelist(struct my_msgbuf *this);
extern void callback_attach_page_buffers(struct my_msgbuf *this);
extern void callback_alloc_percpu(struct my_msgbuf *this);// 宏
extern void callback_read_mapping_page(struct my_msgbuf *this);
extern void callback_zero_user_segments(struct my_msgbuf *this);
extern void callback_zero_user(struct my_msgbuf *this);
extern void callback_cleancache_invalidate_fs(struct my_msgbuf *this);// 调用了定义在mm/cleancache.c中的__cleancache_invalidate_fs()
extern void callback_lock_page(struct my_msgbuf *this);// 调用了定义在mm/filemap.c中的__lock_page()
extern void callback_kmalloc(struct my_msgbuf *this);// 调用了定义在mm/slub.c中的__kmalloc()和定义在mm/slub.c中的kmem_cache_alloc_trace()
extern void callback_grab_cache_page(struct my_msgbuf *this);// 调用了定义在mm/filemap.c中的find_or_create_page()
extern void callback_kmalloc_large(struct my_msgbuf *this);// 调用了定义在mm/slab_common.c中的kmalloc_order_trace()
extern void callback_kzalloc(struct my_msgbuf *this);// 调用了定义在include/linux/slab.h中的kmalloc()

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
extern void callback_in_group_p(struct my_msgbuf *this);
extern void callback_yield(struct my_msgbuf *this);
extern void callback_inode_capable(struct my_msgbuf *this);
extern void callback_task_work_add(struct my_msgbuf *this);
extern void callback_synchronize_rcu(struct my_msgbuf *this);
extern void callback_prepare_to_wait(struct my_msgbuf *this);
extern void callback_schedule(struct my_msgbuf *this);
extern void callback_finish_wait(struct my_msgbuf *this);
extern void callback_current_fs_time(struct my_msgbuf *this);
// extern void callback_lock_is_held(struct my_msgbuf *this);
extern void callback_audit_log_link_denied(struct my_msgbuf *this);
extern void callback_send_sig(struct my_msgbuf *this);
extern void callback_timespec_trunc(struct my_msgbuf *this);
extern void callback_acct_auto_close_mnt(struct my_msgbuf *this);
extern void callback___wait_on_bit(struct my_msgbuf *this);
extern void callback_free_uid(struct my_msgbuf *this);
extern void callback_module_put(struct my_msgbuf *this);
extern void callback_make_kgid(struct my_msgbuf *this);// 这个直接在include/linux/fs.h中的i_gid_write()中发送msg_make_kgid()，因为i_gid_write()使用到了文件系统的数据对象，因此不能发送msg_i_gid_write()
extern void callback_autoremove_wake_function(struct my_msgbuf *this);
extern void callback_current_kernel_time(struct my_msgbuf *this);
extern void callback_mutex_lock(struct my_msgbuf *this);
extern void callback_mutex_unlock(struct my_msgbuf *this);
extern void callback_make_kuid(struct my_msgbuf *this);// 这个直接在include/linux/fs.h中的i_gid_write()中发送msg_make_kgid()，因为i_gid_write()使用到了文件系统的数据对象，因此不能发送msg_i_uid_write()
extern void callback_io_schedule(struct my_msgbuf *this);
extern void callback_lg_local_lock_cpu(struct my_msgbuf *this);
extern void callback_lg_local_unlock_cpu(struct my_msgbuf *this);
extern void callback_warn_slowpath_null(struct my_msgbuf *this);
extern void callback_from_kgid(struct my_msgbuf *this);// 这个直接在include/linux/fs.h中的i_gid_read()中发送msg_from_kgid()，因为i_gid_read()使用到了文件系统的数据对象，因此不能发送msg_i_gid_read()
extern void callback_wake_bit_function(struct my_msgbuf *this);
extern void callback_try_module_get(struct my_msgbuf *this);
extern void callback_from_kuid(struct my_msgbuf *this);// 这个直接在include/linux/fs.h中的i_uid_read()中发送msg_from_kuid()，因为i_uid_read()使用到了文件系统的数据对象，因此不能发送msg_i_uid_read()
extern void callback_destroy_workqueue(struct my_msgbuf *this);
extern void callback_wait_for_completion(struct my_msgbuf *this);
extern void callback___module_get(struct my_msgbuf *this);
extern void callback_call_rcu(struct my_msgbuf *this);
extern void callback_down_read_trylock(struct my_msgbuf *this);

// include-kernel
extern void callback_audit_reusename(struct my_msgbuf *this);
extern void callback_audit_getname(struct my_msgbuf *this);// 调用了定义在kernel/auditsc.c中的__audit_getname()
extern void callback_current_cred(struct my_msgbuf *this);
extern void callback_percpu_counter_inc(struct my_msgbuf *this);
extern void callback_get_cred(struct my_msgbuf *this);
extern void callback_percpu_counter_dec(struct my_msgbuf *this);
extern void callback_current_fsuid(struct my_msgbuf *this);
extern void callback_get_cached_acl_rcu(struct my_msgbuf *this);
extern void callback_local_irq_disable(struct my_msgbuf *this);
extern void callback_local_irq_enable(struct my_msgbuf *this);
extern void callback_might_sleep(struct my_msgbuf *this);
extern void callback_preempt_disable(struct my_msgbuf *this);
extern void callback_preempt_enable(struct my_msgbuf *this);
extern void callback_list_for_each_entry_rcu(struct my_msgbuf *this);
extern void callback_mod_delayed_work(struct my_msgbuf *this);// 调用了定义在kernel/workqueue.c中的mod_delayed_work_on()
extern void callback_css_put(struct my_msgbuf *this);
extern void callback_wake_up_all(struct my_msgbuf *this);
extern void callback_posix_acl_release(struct my_msgbuf *this);
extern void callback_read_seqbegin(struct my_msgbuf *this);
extern void callback_schedule_delayed_work(struct my_msgbuf *this);
extern void callback_dget(struct my_msgbuf *this);
// extern void callback_hlist_bl_for_each_entry_rcu(struct my_msgbuf *this);
extern void callback_hlist_bl_first_rcu(struct my_msgbuf *this);
extern void callback_rcu_dereference_raw(struct my_msgbuf *this);
extern void callback_list_entry_rcu(struct my_msgbuf *this);
extern void callback_cond_resched(struct my_msgbuf *this);
extern void callback_wake_up_interruptible(struct my_msgbuf *this);
extern void callback_seqcount_init(struct my_msgbuf *this);
extern void callback_lockdep_set_class(struct my_msgbuf *this);
extern void callback_mutex_init(struct my_msgbuf *this);
extern void callback_wait_event(struct my_msgbuf *this);
extern void callback_percpu_counter_add(struct my_msgbuf *this);
extern void callback_fops_get(struct my_msgbuf *this);
extern void callback_init_waitqueue_head(struct my_msgbuf *this);// 宏，调用了定义在kernel/sched/wait.c中的__init_waitqueue_head()
extern void callback_wake_up(struct my_msgbuf *this);// 宏，调用了定义在kernel/sched/wait.c中的__wake_up()
extern void callback_wait_event_interruptible_timeout(struct my_msgbuf *this);// 宏，调用了定义在kernel中的abort_exclusive_wait()、finish_wait()、prepare_to_wait_event()、schedule_timeout()等函数
extern void callback_audit_inode(struct my_msgbuf *this);// 调用了定义在kernel/auditsc.c中的__audit_inode()
extern void callback_audit_inode_child(struct my_msgbuf *this);// 调用了定义在kernel/auditsc.c中的__audit_inode_child()
extern void callback_srcu_dereference(struct my_msgbuf *this);
extern void callback_kfree_rcu(struct my_msgbuf *this);
extern void callback_write_lock(struct my_msgbuf *this);// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_lock()
extern void callback_init_rwsem(struct my_msgbuf *this);// 宏，调用了定义在kernel/locking/rwsem-spinlock.c中的__init_rwsem()
extern void callback_queue_delayed_work(struct my_msgbuf *this);// 调用了定义在kernel/workqueue.c中的queue_delayed_work_on()
extern void callback_spin_lock(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock()
extern void callback_spin_unlock(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock()
extern void callback_spin_lock_irq(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock_irq()
extern void callback_spin_unlock_irq(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_irq()
extern void callback_spin_trylock(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_trylock()
extern void callback_WARN_ON(struct my_msgbuf *this);// 宏，调用了定义在kernel/panic.c中的warn_slowpath_null()
extern void callback_printk_ratelimit(struct my_msgbuf *this);// 宏，调用了定义在kernel/printk/printk.c中的__printk_ratelimit()
extern void callback_wait_on_bit_lock(struct my_msgbuf *this);// 调用了定义在kernel/sched/wait.c中的out_of_line_wait_on_bit_lock()
extern void callback_write_lock_irq(struct my_msgbuf *this);// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_lock_irq()
extern void callback_write_unlock_irq(struct my_msgbuf *this);// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_unlock_irq()
extern void callback_read_lock(struct my_msgbuf *this);// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_read_lock()
extern void callback_read_unlock(struct my_msgbuf *this);// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_read_unlock()
extern void callback_spin_unlock_irqrestore(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_irqrestore()
extern void callback_queue_work(struct my_msgbuf *this);// 调用了定义在kernel/workqueue.c中的queue_work_on()
extern void callback_spin_lock_bh(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock_bh()
extern void callback_spin_unlock_bh(struct my_msgbuf *this);// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_bh()

/* 文件系统与通用块层的交互 */
extern void callback_bdevname(struct my_msgbuf *this);
extern void callback_submit_bio(struct my_msgbuf *this);
extern void callback_put_io_context(struct my_msgbuf *this);
extern void callback_blk_finish_plug(struct my_msgbuf *this);
extern void callback_blk_start_plug(struct my_msgbuf *this);

#endif
