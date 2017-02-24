#ifndef __LINUX_CALLBACK_XXX_H
#define __LINUX_CALLBACK_XXX_H

#include <linux/lockdep.h>
#include <linux/my_msg.h>
// #include <linux/my_msg.h>
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


/* 文件系统与通用块层的交互 */
extern void callback_bdevname(struct my_msgbuf *this);
extern void callback_submit_bio(struct my_msgbuf *this);
extern void callback_put_io_context(struct my_msgbuf *this);

#endif
