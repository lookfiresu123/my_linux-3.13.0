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
#include <linux/mmzone.h>
#include <linux/nodemask.h>
#include <linux/gfp.h>
#include <linux/buffer_head.h>
#include <linux/highmem.h>
#include <linux/cleancache.h>
#include <linux/audit.h>
#include <linux/percpu_counter.h>
#include <linux/cred.h>
#include <linux/posix_acl.h>
#include <linux/workqueue.h>
#include <linux/cgroup.h>
#include <linux/seqlock.h>
#include <linux/dcache.h>
#include <linux/rculist.h>
#include <linux/seqlock.h>
#include <linux/rculist_bl.h>
#include <linux/mutex.h>
#include <linux/srcu.h>
#include <linux/mount.h>
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
#include <linux/interactive_design.h>

// extern int lock_is_held(struct lockdep_map *lock);

struct mnt_pcp_copy {
  int mnt_count;
  int mnt_writers;
};

/* 接收方一般直接调用 recvbuf.callback(&recvbuf); */

/*
 * 文件系统与内存模块的交互实现
 */
void callback_kmem_cache_alloc(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct kmem_cache *, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kmem_cache_alloc(ptr->argu1, ptr->argu2);// kmem_cache_alloc()函数
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_kmem_cache_free(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct kmem_cache *, void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kmem_cache_free(ptr->argu1, ptr->argu2);// kmem_cache_free()函数
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_kfree(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(const void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kfree(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_vfree(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(const void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  vfree(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_mempool_alloc(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(mempool_t *, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = mempool_alloc(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_mempool_free(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(void *, mempool_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  mempool_free(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_page_mapping(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct address_space *ret = page_mapping(ptr->argu1);
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_list_lru_add(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct list_lru *, struct list_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = list_lru_add(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_list_lru_del(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct list_lru *, struct list_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = list_lru_del(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_find_get_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct address_space *, pgoff_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = find_get_page(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_mark_page_accessed(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  mark_page_accessed(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_find_or_create_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct address_space *, pgoff_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = find_or_create_page(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_cancel_dirty_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct page *, unsigned int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  cancel_dirty_page(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_page_address(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(const struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = page_address(ptr->argu1);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_bdi_has_dirty_io(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct backing_dev_info *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = bdi_has_dirty_io(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}


void callback_try_to_free_pages(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg4(struct zonelist *, int, gfp_t, nodemask_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unsigned long ret = try_to_free_pages(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = kmalloc(sizeof(unsigned long), GFP_KERNEL);
  *(unsigned long *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_unlock_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unlock_page(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_account_page_dirtied(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct page *, struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  account_page_dirtied(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_bdi_wakeup_thread_delayed(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct backing_dev_info *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bdi_wakeup_thread_delayed(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_kstrdup(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(const char *, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  char *ret = kstrdup(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_free_percpu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(void __percpu *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  free_percpu(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_kmemdup(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(const void *, size_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kmemdup(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_file_ra_state_init(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct file_ra_state *, struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  file_ra_state_init(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_write_one_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct page *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = write_one_page(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_truncate_setsize(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct inode *, loff_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  truncate_setsize(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_mapping_tagged(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct address_space *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = mapping_tagged(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_do_writepages(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct address_space *, struct writeback_control *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = do_writepages(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_filemap_fdatawait(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = filemap_fdatawait(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_truncate_inode_pages(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct address_space *, loff_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  truncate_inode_pages(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_unregister_shrinker(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct shrinker *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unregister_shrinker(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_list_lru_destroy(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct list_lru *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  list_lru_destroy(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_kmem_cache_create(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg5(const char *, size_t, size_t, unsigned long, ctor_func_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct kmem_cache *ret = kmem_cache_create(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4, ptr->argu5);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_read_cache_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg4(struct address_space *, pgoff_t, filler_func_t, void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = read_cache_page(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_migrate_page_copy(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct page *, struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  migrate_page_copy(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_migrate_page_move_mapping(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg6(struct address_space *, struct page *, struct page *, struct buffer_head *, enum migrate_mode, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = migrate_page_move_mapping(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4, ptr->argu5, ptr->argu6);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_put_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  put_page(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

/*
void callback_find_or_create_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct address_space *, pgoff_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = find_or_create_page(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}
*/

void callback_filemap_write_and_wait(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = filemap_write_and_wait(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_filemap_flush(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = filemap_flush(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_get_user_pages(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg8(struct task_struct *, struct mm_struct *, unsigned long, unsigned long, int, int, struct page **, struct vm_area_struct **) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  long ret = get_user_pages(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4, ptr->argu5, ptr->argu6, ptr->argu7, ptr->argu8);
  this->object_ptr = kmalloc(sizeof(long), GFP_KERNEL);
  *(long *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_register_shrinker(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct shrinker *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = register_shrinker(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_set_page_dirty(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = set_page_dirty(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// include-mm
void callback_kmem_cache_zalloc(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct kmem_cache *, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kmem_cache_zalloc(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_page_cache_release(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  page_cache_release(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_first_zones_zonelist(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg4(struct zonelist *, enum zone_type, nodemask_t *, struct zone **) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct zoneref *ret = first_zones_zonelist(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_node_zonelist(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(int, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct zonelist *ret = node_zonelist(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_attach_page_buffers(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct page *, struct buffer_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  attach_page_buffers(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_alloc_percpu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct mnt_pcp *ret = alloc_percpu(struct mnt_pcp);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_read_mapping_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct address_space *, pgoff_t, void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = read_mapping_page(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_zero_user_segments(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg5(struct page *, unsigned, unsigned, unsigned, unsigned) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  zero_user_segments(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4, ptr->argu5);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_zero_user(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct page *, unsigned, unsigned) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  zero_user(ptr->argu1, ptr->argu2, ptr->argu3);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_cleancache_invalidate_fs(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct super_block *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  cleancache_invalidate_fs(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在mm/filemap.c中的__lock_page()
void callback_lock_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  lock_page(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在mm/slub.c中的__kmalloc()和定义在mm/slub.c中的kmem_cache_alloc_trace()
void callback_kmalloc(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(size_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kmalloc(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在mm/filemap.c中的find_or_create_page()
void callback_grab_cache_page(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct address_space *, pgoff_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = grab_cache_page(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在mm/slab_common.c中的kmalloc_order_trace()
void callback_kmalloc_large(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(size_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kmalloc_large(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在include/linux/slab.h中的kmalloc()
void callback_kzalloc(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(size_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kzalloc(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}


/*
 * 文件系统与内核模块的交互实现
 */
void callback_capable(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = capable(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_down_read(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  down_read(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_up_read(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  up_read(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_down_write(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  down_write(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_up_write(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  up_write(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wake_up_bit(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(void *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wake_up_bit(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_bit_waitqueue(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(void *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wait_queue_head_t *ret = bit_waitqueue(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_get_seconds(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unsigned long ret = get_seconds();
  this->object_ptr = kmalloc(sizeof(unsigned long), GFP_KERNEL);
  *(unsigned long *)(this->object_ptr) = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_put_pid(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct pid *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  put_pid(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_in_group_p(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(kgid_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = in_group_p(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_yield(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  yield();
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_inode_capable(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(const struct inode *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = inode_capable(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_task_work_add(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct task_struct *, struct callback_head *, bool) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = task_work_add(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_synchronize_rcu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  synchronize_rcu();
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_prepare_to_wait(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(wait_queue_head_t *, wait_queue_t *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  prepare_to_wait(ptr->argu1, ptr->argu2, ptr->argu3);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_schedule(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  schedule();
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_finish_wait(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(wait_queue_head_t *, wait_queue_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  finish_wait(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_current_fs_time(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct super_block *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct timespec ret = current_fs_time(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(struct timespec), GFP_KERNEL);
  ((struct timespec *)(this->object_ptr))->tv_sec = ret.tv_sec;// 保存返回值
  ((struct timespec *)(this->object_ptr))->tv_nsec = ret.tv_nsec;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_audit_log_link_denied(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(const char *, struct path *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  audit_log_link_denied(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_send_sig(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(int, struct task_struct *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = send_sig(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_timespec_trunc(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct timespec, unsigned) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct timespec ret = timespec_trunc(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(struct timespec), GFP_KERNEL);
  ((struct timespec *)(this->object_ptr))->tv_sec = ret.tv_sec;// 保存返回值
  ((struct timespec *)(this->object_ptr))->tv_nsec = ret.tv_nsec;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_acct_auto_close_mnt(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct vfsmount *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  acct_auto_close_mnt(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback___wait_on_bit(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg4(wait_queue_head_t *, struct wait_bit_queue *, action_func_t, unsigned) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = __wait_on_bit(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_free_uid(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct user_struct *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  free_uid(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_module_put(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct module *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  module_put(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 这个直接在include/linux/fs.h中的i_gid_write()中发送msg_make_kgid()，因为i_gid_write()使用到了文件系统的数据对象，因此不能发送msg_i_gid_write()
void callback_make_kgid(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct user_namespace *, gid_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kgid_t ret = make_kgid(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(kgid_t), GFP_KERNEL);
  *(kgid_t *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_autoremove_wake_function(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg4(wait_queue_t *, unsigned, int, void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = autoremove_wake_function(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_current_kernel_time(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct timespec ret = current_kernel_time();
  this->object_ptr = kmalloc(sizeof(struct timespec), GFP_KERNEL);
  ((struct timespec *)(this->object_ptr))->tv_sec = ret.tv_sec;// 保存返回值
  ((struct timespec *)(this->object_ptr))->tv_nsec = ret.tv_nsec;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_mutex_lock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct mutex *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  mutex_lock(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_mutex_unlock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct mutex *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  mutex_unlock(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 这个直接在include/linux/fs.h中的i_gid_write()中发送msg_make_kgid()，因为i_gid_write()使用到了文件系统的数据对象，因此不能发送msg_i_uid_write()
void callback_make_kuid(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct user_namespace *, uid_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kuid_t ret = make_kuid(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(kuid_t), GFP_KERNEL);
  *(kuid_t *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_io_schedule(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  io_schedule();
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_lg_local_lock_cpu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct lglock *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  lg_local_lock_cpu(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_lg_local_unlock_cpu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct lglock *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  lg_local_unlock_cpu(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_warn_slowpath_null(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(const char *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  warn_slowpath_null(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 这个直接在include/linux/fs.h中的i_gid_read()中发送msg_from_kgid()，因为i_gid_read()使用到了文件系统的数据对象，因此不能发送msg_i_gid_read()
void callback_from_kgid(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct user_namespace *, kgid_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  gid_t ret = from_kgid(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(gid_t), GFP_KERNEL);
  *(gid_t *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wake_bit_function(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg4(wait_queue_t *, unsigned, int, void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = wake_bit_function(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_try_module_get(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct module *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = try_module_get(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 这个直接在include/linux/fs.h中的i_uid_read()中发送msg_from_kuid()，因为i_uid_read()使用到了文件系统的数据对象，因此不能发送msg_i_uid_read()
void callback_from_kuid(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct user_namespace *, kuid_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  uid_t ret = from_kuid(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(uid_t), GFP_KERNEL);
  *(uid_t *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_destroy_workqueue(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct workqueue_struct *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  destroy_workqueue(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wait_for_completion(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct completion *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wait_for_completion(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback___module_get(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct module *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  __module_get(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_call_rcu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct rcu_head *, func_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  call_rcu(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_down_read_trylock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = down_read_trylock(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// include-kernel
void callback_audit_reusename(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(const __user char *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct filename *ret = audit_reusename(ptr->argu1);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_audit_getname(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct filename *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  audit_getname(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 无参宏
void callback_current_cred(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  const struct cred *ret = current_cred();
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_percpu_counter_inc(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct percpu_counter *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  percpu_counter_inc(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_get_cred(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(const struct cred *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  const struct cred *ret = get_cred(ptr->argu1);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_percpu_counter_dec(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct percpu_counter *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  percpu_counter_dec(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 无参宏
void callback_current_fsuid(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kuid_t ret = current_fsuid();
  this->object_ptr = kmalloc(sizeof(kuid_t), GFP_KERNEL);
  *(kuid_t *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_get_cached_acl_rcu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct inode *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct posix_acl *ret = get_cached_acl_rcu(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_local_irq_disable(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  local_irq_disable();
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_local_irq_enable(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  local_irq_enable();
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_might_sleep(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  might_sleep();
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_preempt_disable(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  preempt_disable();
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_preempt_enable(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  preempt_enable();
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 带参宏，展开宏定义并用已经写好的msg_list_entry_rcu替换list_entry_rcu
void callback_list_for_each_entry_rcu(struct my_msgbuf *this) {

}

void callback_mod_delayed_work(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct workqueue_struct *, struct delayed_work *, unsigned long) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = mod_delayed_work(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_css_put(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct cgroup_subsys_state *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  css_put(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wake_up_all(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(wait_queue_head_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wake_up_all(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}


void callback_posix_acl_release(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct posix_acl *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  posix_acl_release(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_read_seqbegin(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(const seqlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unsigned ret = read_seqbegin(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(unsigned), GFP_KERNEL);
  *(unsigned *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_schedule_delayed_work(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct delayed_work *, unsigned long) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = schedule_delayed_work(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_dget(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct dentry *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct dentry *ret = dget(ptr->argu1);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

/* 为hlist_bl_for_each_entry_rcu而写的两个函数，需要在代码处将该宏定义展开*/
void callback_hlist_bl_first_rcu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct hlist_bl_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct hlist_bl_node *ret = hlist_bl_first_rcu(ptr->argu1);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_rcu_dereference_raw(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct hlist_bl_node *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct hlist_bl_node *ret = rcu_dereference_raw(ptr->argu1);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}


void callback_list_entry_rcu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct list_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct dentry *ret = list_entry_rcu(ptr->argu1, struct dentry, d_lru);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_cond_resched(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = cond_resched();
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wake_up_interruptible(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct __wait_queue_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wake_up_interruptible(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_seqcount_init(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(seqcount_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  seqcount_init(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

/*
void callback_lockdep_set_class(struct my_msgbuf *this) {

}
*/

void callback_mutex_init(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct mutex *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  mutex_init(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wait_event(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct __wait_queue_head, bool) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wait_event(ptr->argu1, ptr->argu2);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_percpu_counter_add(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct percpu_counter *, s64) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  percpu_counter_add(ptr->argu1, ptr->argu2);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_fops_get(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(const struct file_operations	*) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  const struct file_operations *ret = fops_get(ptr->argu1);
  this->object_ptr = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_init_waitqueue_head(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct __wait_queue_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  init_waitqueue_head(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wake_up(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct __wait_queue_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wake_up(ptr->argu1);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_wait_event_interruptible_timeout(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct __wait_queue_head, bool, unsigned long) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = wait_event_interruptible_timeout(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_audit_inode(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct filename *, const struct dentry *, unsigned int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  audit_inode(ptr->argu1, ptr->argu2, ptr->argu3);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_audit_inode_child(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(const struct inode *, const struct dentry *, const unsigned char) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  audit_inode_child(ptr->argu1, ptr->argu2, ptr->argu3);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_srcu_dereference(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct hlist_node *, struct srcu_struct *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = srcu_dereference(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_kfree_rcu(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct super_block *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kfree_rcu(ptr->argu1, rcu);
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_lock()
void callback_write_lock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(rwlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  write_lock(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/locking/rwsem-spinlock.c中的__init_rwsem()
void callback_init_rwsem(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  init_rwsem(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/workqueue.c中的queue_delayed_work_on()
void callback_queue_delayed_work(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg3(struct workqueue_struct *, struct delayed_work *, unsigned long) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = queue_delayed_work(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock()
void callback_spin_lock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(spinlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_lock(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock()
void callback_spin_unlock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(spinlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_unlock(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock_irq()
void callback_spin_lock_irq(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(spinlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_lock_irq(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_irq()
void callback_spin_unlock_irq(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(spinlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_unlock_irq(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_trylock()
void callback_spin_trylock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(spinlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_trylock(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/panic.c中的warn_slowpath_null()
void callback_WARN_ON(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(bool) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  WARN_ON(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/printk/printk.c中的__printk_ratelimit()
void callback_printk_ratelimit(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = printk_ratelimit();
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/sched/wait.c中的out_of_line_wait_on_bit_lock()
void callback_wait_on_bit_lock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg4(void *, int, action_func_t, unsigned) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = wait_on_bit_lock(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_lock_irq()
void callback_write_lock_irq(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(rwlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  write_lock_irq(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_write_unlock_irq()
void callback_write_unlock_irq(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(rwlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  write_unlock_irq(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_read_lock()
void callback_read_lock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(rwlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  read_lock(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 宏，调用了定义在kernel/locking/spinlock.c中的_raw_read_unlock()
void callback_read_unlock(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(rwlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  read_unlock(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_irqrestore()
void callback_spin_unlock_irqrestore(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(spinlock_t *, unsigned long) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_unlock_irqrestore(ptr->argu1, ptr->argu2);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/workqueue.c中的queue_work_on()
void callback_queue_work(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct workqueue_struct *, struct work_struct *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = queue_work(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_lock_bh()
void callback_spin_lock_bh(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(spinlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_lock_bh(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

// 调用了定义在kernel/locking/spinlock.c中的_raw_spin_unlock_bh()
void callback_spin_unlock_bh(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(spinlock_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  spin_unlock_bh(ptr->argu1);
  // 无需传递返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}



/*
 * 文件系统与通用块层的交互实现
 */
void callback_bdevname(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(struct block_device *, char *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  const char *ret = bdevname(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_submit_bio(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg2(int, struct bio *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  submit_bio(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_put_io_context(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct io_context *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  put_io_context(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_blk_finish_plug(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct blk_plug *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  blk_finish_plug(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}

void callback_blk_start_plug(struct my_msgbuf *this) {
  MY_PRINTK(get_current()->comm);
  typedef Argus_msg1(struct blk_plug *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  blk_start_plug(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this);
  my_msgsendB(this, sendlength);
}