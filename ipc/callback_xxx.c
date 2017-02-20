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
  this->object_ptr = (unsigned long *)kmalloc(sizeof(unsigned long), GFP_KERNEL);
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
