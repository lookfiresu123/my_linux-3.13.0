#include <linux/my_msg.h>
#include <linux/msg_xxx.h>
#include <linux/callback_xxx.h>
#include <linux/interactive_design.h>

int msqid_from_fs_to_kernel;
EXPORT_SYMBOL(msqid_from_fs_to_kernel);
int msqid_from_kernel_to_fs;
EXPORT_SYMBOL(msqid_from_kernel_to_fs);

// 初始化消息块中的部分成员
static void init_msgbuf(struct my_msgbuf *sendbuf_ptr, int mtype, struct task_struct *tsk, int msqid, bool isend, void (*callback_xxx)(struct msgbuf *)) {
  sendbuf_ptr->mtype = mtype;
  sendbuf_ptr->tsk = tsk;
  sendbuf_ptr->callback = callback_xxx;
  sendbuf_ptr->msqid = msqid;
  sendbuf_ptr->isend = 0;
}

/*
 * 文件系统与内存模块的交互实现
 */
void *msg_kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_kmem_cache_alloc);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct kmem_cache *, gfp_t) Argus_type;
    Argus_type argus;
    argus.argu1 = s;
    argus.argu2 = gfpflags;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    void *ret = sendbuf.object_ptr;// 每个msg_xxx()函数处理返回值的方法都不同
    return ret;
  } else
    return kmem_cache_alloc(s, gfpflags);
}

void msg_kmem_cache_free(struct kmem_cache *s, void *x, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
     // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_kmem_cache_free);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct kmem_cache *, void *) Argus_type;
    Argus_type argus;
    argus.argu1 = s;
    argus.argu2 = x;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需处理返回值
  } else
    kmem_cache_free(s, x);
}

void msg_kfree(const void *x, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_kfree);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(const void *) Argus_type;
    Argus_type argus;
    argus.argu1 = x;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需处理返回值
  } else
    kfree(x);
}

void msg_vfree(const void *addr, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_vfree);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(const void *) Argus_type;
    Argus_type argus;
    argus.argu1 = addr;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需处理返回值
  } else
    vfree(addr);
}

void *msg_mempool_alloc(mempool_t *pool, gfp_t gfp_mask, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_mempool_alloc);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(mempool_t *, gfp_t) Argus_type;
    Argus_type argus;
    argus.argu1 = pool;
    argus.argu2 = gfp_mask;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    void *ret = sendbuf.object_ptr;
    return ret;
  } else
    return mempool_alloc(pool, gfp_mask);
}

void msg_mempool_free(void *element, mempool_t *pool, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_mempool_free);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(void *, mempool_t *) Argus_type;
    Argus_type argus;
    argus.argu1 = element;
    argus.argu2 = pool;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需处理返回值
  } else
    mempool_free(element, pool);
}

struct address_space *msg_page_mapping(struct page *page, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_page_mapping);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct page *) Argus_type;
    Argus_type argus;
    argus.argu1 = page;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    struct address_space *ret = sendbuf.object_ptr;
    return ret;
  } else
    return page_mapping(page);
}

bool msg_list_lru_add(struct list_lru *lru, struct list_head *item, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_list_lru_add);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct list_lru *, struct list_head *) Argus_type;
    Argus_type argus;
    argus.argu1 = lru;
    argus.argu2 = item;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    bool ret = *(bool *)(sendbuf.object_ptr);
    return ret;
  } else
    return list_lru_add(lru, item);
}

bool msg_list_lru_del(struct list_lru *lru, struct list_head *item, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_list_lru_del);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct list_lru *, struct list_head *) Argus_type;
    Argus_type argus;
    argus.argu1 = lru;
    argus.argu2 = item;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    bool ret = *(bool *)(sendbuf.object_ptr);
    return ret;
  } else
    return list_lru_del(lru, item);
}

/*
 * 文件系统与内核模块的交互实现
 */
bool msg_capable(int cap, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_capable);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(int) Argus_type;
    Argus_type argus;
    argus.argu1 = cap;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    bool ret = *(bool *)(sendbuf.object_ptr);
    return ret;
  } else
    return capable(cap);
}

void msg_down_read(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_down_read);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct rw_semaphore *) Argus_type;
    Argus_type argus;
    argus.argu1 = sem;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需存储返回值
  } else
    down_read(sem);
}

void msg_up_read(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_up_read);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct rw_semaphore *) Argus_type;
    Argus_type argus;
    argus.argu1 = sem;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需存储返回值
  } else
    up_read(sem);
}

void msg_down_write(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_down_write);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct rw_semaphore *) Argus_type;
    Argus_type argus;
    argus.argu1 = sem;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需存储返回值
  } else
    down_write(sem);
}

void msg_up_write(struct rw_semaphore *sem, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_up_write);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct rw_semaphore *) Argus_type;
    Argus_type argus;
    argus.argu1 = sem;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需存储返回值
  } else
    up_write(sem);
}

void msg_wake_up_bit(void *word, int bit, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_wake_up_bit);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(void *, int) Argus_type;
    Argus_type argus;
    argus.argu1 = word;
    argus.argu2 = bit;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    // 无需存储返回值
  } else
    wake_up_bit(word, bit);
}

wait_queue_head_t *msg_bit_waitqueue(void *word, int bit, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_bit_waitqueue);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(void *, int) Argus_type;
    Argus_type argus;
    argus.argu1 = word;
    argus.argu2 = bit;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    wait_queue_head_t *ret = sendbuf.object_ptr;
    return ret;
  } else
    return bit_waitqueue(word, bit);
}

unsigned long msg_get_seconds(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_get_seconds);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg0() Argus_type;
    Argus_type argus;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    unsigned long ret = *(unsigned long *)(sendbuf.object_ptr);
    return ret;
  } else
    return get_seconds();
}

void msg_put_pid(struct pid *pid, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_put_pid);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct pid *) Argus_type;
    Argus_type argus;
    argus.argu1 = pid;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    put_pid(pid);
}

/*
 * 文件系统与通用块层的交互实现
 */
void msg_bdevname(struct block_device *bdev, char *buf, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_bdevname);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct block_device *, char *) Argus_type;
    Argus_type argus;
    argus.argu1 = bdev;
    argus.argu2 = buf;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    const char *ret = (const char *)(sendbuf.object_ptr);
    return ret;
  } else
    return bdevname(bdev, buf);
}

void msg_submit_bio(int rw, struct bio *bio, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_submit_bio);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(int, struct bio *) Argus_type;
    Argus_type argus;
    argus.argu1 = rw;
    argus.argu2 = bio;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    submit_bio(rw, bio);
}

void msg_put_io_context(struct io_context *ioc, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(current->comm);
  if (my_strcmp(current->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, current, msqid_from_kernel_to_fs, false, callback_put_io_context);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct io_context *) Argus_type;
    Argus_type argus;
    argus.argu1 = ioc;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    put_io_context(ioc);
}
