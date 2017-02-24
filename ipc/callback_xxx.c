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

// extern int lock_is_held(struct lockdep_map *lock);

/* 接收方一般直接调用 recvbuf.callback(&recvbuf); */

/*
 * 文件系统与内存模块的交互实现
 */
void callback_kmem_cache_alloc(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct kmem_cache *, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kmem_cache_alloc(ptr->argu1, ptr->argu2);// kmem_cache_alloc()函数
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_kmem_cache_free(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct kmem_cache *, void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kmem_cache_free(ptr->argu1, ptr->argu2);// kmem_cache_free()函数
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_kfree(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(const void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  kfree(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_vfree(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(const void *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  vfree(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_mempool_alloc(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(mempool_t *, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = mempool_alloc(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_mempool_free(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(void *, mempool_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  mempool_free(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_page_mapping(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct address_space *ret = page_mapping(ptr->argu1);
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_list_lru_add(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct list_lru *, struct list_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = list_lru_add(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_list_lru_del(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct list_lru *, struct list_head *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = list_lru_del(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_find_get_page(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct address_space *, pgoff_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = find_get_page(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_mark_page_accessed(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  mark_page_accessed(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_find_or_create_page(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg3(struct address_space *, pgoff_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct page *ret = find_or_create_page(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_cancel_dirty_page(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct page *, unsigned int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  cancel_dirty_page(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_page_address(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(const struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = page_address(ptr->argu1);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_bdi_has_dirty_io(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct backing_dev_info *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = bdi_has_dirty_io(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}


void callback_try_to_free_pages(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg4(struct zonelist *, int, gfp_t, nodemask_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unsigned long ret = try_to_free_pages(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = kmalloc(sizeof(unsigned long), GFP_KERNEL);
  *(unsigned long *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_unlock_page(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct page *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unlock_page(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_account_page_dirtied(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct page *, struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  account_page_dirtied(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_bdi_wakeup_thread_delayed(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct backing_dev_info *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bdi_wakeup_thread_delayed(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_kstrdup(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(const char *, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  char *ret = kstrdup(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_free_percpu(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(void __percpu *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  free_percpu(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_kmemdup(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg3(const void *, size_t, gfp_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  void *ret = kmemdup(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_file_ra_state_init(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct file_ra_state *, struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  file_ra_state_init(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_write_one_page(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct page *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = write_one_page(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_truncate_setsize(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct inode *, loff_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  truncate_setsize(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_mapping_tagged(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct address_space *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = mapping_tagged(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_do_writepages(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct address_space *, struct writeback_control *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = do_writepages(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_filemap_fdatawait(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct address_space *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = filemap_fdatawait(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_truncate_inode_pages(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct address_space *, loff_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  truncate_inode_pages(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_unregister_shrinker(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct shrinker *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unregister_shrinker(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_list_lru_destroy(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct list_lru *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  list_lru_destroy(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}



/*
 * 文件系统与内核模块的交互实现
 */
void callback_capable(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = capable(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_down_read(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  down_read(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_up_read(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  up_read(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_down_write(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  down_write(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_up_write(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct rw_semaphore *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  up_write(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_wake_up_bit(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(void *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wake_up_bit(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_bit_waitqueue(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(void *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  wait_queue_head_t *ret = bit_waitqueue(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_get_seconds(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  unsigned long ret = get_seconds();
  this->object_ptr = kmalloc(sizeof(unsigned long), GFP_KERNEL);
  *(unsigned long *)(this->object_ptr) = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_put_pid(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct pid *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  put_pid(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_in_group_p(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(kgid_t) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = in_group_p(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_yield(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  yield();
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_inode_capable(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(const struct inode *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  bool ret = inode_capable(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(bool), GFP_KERNEL);
  *(bool *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_task_work_add(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg3(struct task_struct *, struct callback_head *, bool) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = task_work_add(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_synchronize_rcu(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  synchronize_rcu();
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_prepare_to_wait(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg3(wait_queue_head_t *, wait_queue_t *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  prepare_to_wait(ptr->argu1, ptr->argu2, ptr->argu3);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_schedule(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg0() Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  schedule();
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_finish_wait(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(wait_queue_head_t *, wait_queue_t *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  finish_wait(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_current_fs_time(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct super_block *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct timespec ret = current_fs_time(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(struct timespec), GFP_KERNEL);
  ((struct timespec *)(this->object_ptr))->tv_sec = ret.tv_sec;// 保存返回值
  ((struct timespec *)(this->object_ptr))->tv_nsec = ret.tv_nsec;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

/*
void callback_lock_is_held(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct lockdep_map *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = lock_is_held(ptr->argu1);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}
*/

void callback_audit_log_link_denied(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(const char *, struct path *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  audit_log_link_denied(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_send_sig(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg3(int, struct task_struct *, int) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = send_sig(ptr->argu1, ptr->argu2, ptr->argu3);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_timespec_trunc(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct timespec, unsigned) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  struct timespec ret = timespec_trunc(ptr->argu1, ptr->argu2);
  this->object_ptr = kmalloc(sizeof(struct timespec), GFP_KERNEL);
  ((struct timespec *)(this->object_ptr))->tv_sec = ret.tv_sec;// 保存返回值
  ((struct timespec *)(this->object_ptr))->tv_nsec = ret.tv_nsec;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_acct_auto_close_mnt(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct vfsmount *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  acct_auto_close_mnt(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback___wait_on_bit(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg4(wait_queue_head_t *, struct wait_bit_queue *, action_func_t, unsigned) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  int ret = __wait_on_bit(ptr->argu1, ptr->argu2, ptr->argu3, ptr->argu4);
  this->object_ptr = kmalloc(sizeof(int), GFP_KERNEL);
  *(int *)(this->object_ptr) = ret;// 保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_free_uid(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct user_struct *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  free_uid(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_module_put(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct module *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  module_put(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}



/*
 * 文件系统与通用块层的交互实现
 */
void callback_bdevname(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(struct block_device *, char *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  const char *ret = bdevname(ptr->argu1, ptr->argu2);
  this->object_ptr = ret;//保存返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_submit_bio(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg2(int, struct bio *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  submit_bio(ptr->argu1, ptr->argu2);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}

void callback_put_io_context(struct my_msgbuf *this) {
  MY_PRINTK(current->comm);
  typedef Argus_msg1(struct io_context *) Argus_type;
  Argus_type *ptr = (Argus_type *)(this->argus_ptr);
  put_io_context(ptr->argu1);
  // 无需存储返回值
  // 返回消息给发送方
  int sendlength = sizeof(*this) - sizeof(long);
  int flag = my_msgsnd(this->msqid, this, sendlength, 0);
}
