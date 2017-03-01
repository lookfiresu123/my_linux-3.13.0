#include <linux/my_msg.h>
#include <linux/msg_xxx.h>
#include <linux/callback_xxx.h>
#include <linux/interactive_design.h>

// extern int lock_is_held(struct lockdep_map *lock);

int msqid_from_fs_to_kernel;
EXPORT_SYMBOL(msqid_from_fs_to_kernel);
int msqid_from_kernel_to_fs;
EXPORT_SYMBOL(msqid_from_kernel_to_fs);
struct task_struct *fs_temp;
EXPORT_SYMBOL(fs_temp);
bool fs_start = false;
EXPORT_SYMBOL(fs_start);

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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_kmem_cache_alloc);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
     // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_kmem_cache_free);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_kfree);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_vfree);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_mempool_alloc);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_mempool_free);
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
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_page_mapping);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_list_lru_add);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_list_lru_del);
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

struct page *msg_find_get_page(struct address_space *mapping, pgoff_t index, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_find_get_page);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct address_space *, pgoff_t) Argus_type;
    Argus_type argus;
    argus.argu1 = mapping;
    argus.argu2 = index;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    struct page *ret = (struct page *)(sendbuf.object_ptr);
    return ret;
  } else
    return find_get_page(mapping, index);
}

void msg_mark_page_accessed(struct page *page, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_mark_page_accessed);
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
    // 无需处理返回值
  } else
    mark_page_accessed(page);
}

struct page *msg_find_or_create_page(struct address_space *mapping, pgoff_t index, gfp_t gfp_mask, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_find_or_create_page);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg3(struct address_space *, pgoff_t, gfp_t) Argus_type;
    Argus_type argus;
    argus.argu1 = mapping;
    argus.argu2 = index;
    argus.argu3 = gfp_mask;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    struct page *ret = (struct page *)(sendbuf.object_ptr);
    return ret;
  } else
    return find_or_create_page(mapping, index, gfp_mask);
}

void msg_cancel_dirty_page(struct page *page, unsigned int account_size, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_cancel_dirty_page);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct page *, unsigned int) Argus_type;
    Argus_type argus;
    argus.argu1 = page;
    argus.argu2 = account_size;
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
    cancel_dirty_page(page, account_size);
}

void *msg_page_address(const struct page *page, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_page_address);
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
    void *ret = sendbuf.object_ptr;
    return ret;
  } else
    return page_address(page);
}

int msg_bdi_has_dirty_io(struct backing_dev_info *bdi, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_bdi_has_dirty_io);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct backing_dev_info *) Argus_type;
    Argus_type argus;
    argus.argu1 = bdi;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return bdi_has_dirty_io(bdi);
}

unsigned long msg_try_to_free_pages(struct zonelist *zonelist, int order, gfp_t gfp_mask, nodemask_t *mask, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_try_to_free_pages);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg4(struct zonelist *, int, gfp_t, nodemask_t *) Argus_type;
    Argus_type argus;
    argus.argu1 = zonelist;
    argus.argu2 = order;
    argus.argu3 = gfp_mask;
    argus.argu4 = mask;
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
    return try_to_free_pages(zonelist, order, gfp_mask, mask);
}

void msg_unlock_page(struct page *page, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_unlock_page);
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
    // 无需处理返回值
  } else
    unlock_page(page);
}

void msg_account_page_dirtied(struct page *page, struct address_space *mapping, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_account_page_dirtied);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct page *, struct address_space *) Argus_type;
    Argus_type argus;
    argus.argu1 = page;
    argus.argu2 = mapping;
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
    account_page_dirtied(page, mapping);
}

void msg_bdi_wakeup_thread_delayed(struct backing_dev_info *bdi, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_bdi_wakeup_thread_delayed);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct backing_dev_info *) Argus_type;
    Argus_type argus;
    argus.argu1 = bdi;
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
    bdi_wakeup_thread_delayed(bdi);
}

char *msg_kstrdup(const char *s, gfp_t gfp, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_kstrdup);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(const char *, gfp_t) Argus_type;
    Argus_type argus;
    argus.argu1 = s;
    argus.argu2 = gfp;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    char *ret = (char *)(sendbuf.object_ptr);
    return ret;
  } else
    return kstrdup(s, gfp);
}

void msg_free_percpu(void __percpu *__pdata, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_free_percpu);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(void __percpu *) Argus_type;
    Argus_type argus;
    argus.argu1 = __pdata;
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
    free_percpu(__pdata);
}

void *msg_kmemdup(const void *src, size_t len, gfp_t gfp, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_kmemdup);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg3(const void *, size_t, gfp_t) Argus_type;
    Argus_type argus;
    argus.argu1 = src;
    argus.argu2 = len;
    argus.argu2 = gfp;
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
    return kmemdup(src, len, gfp);
}

void msg_file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_file_ra_state_init);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct file_ra_state *, struct address_space *) Argus_type;
    Argus_type argus;
    argus.argu1 = ra;
    argus.argu2 = mapping;
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
    file_ra_state_init(ra, mapping);
}

int msg_write_one_page(struct page *page, int wait, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_write_one_page);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct page *, int) Argus_type;
    Argus_type argus;
    argus.argu1 = page;
    argus.argu2 = wait;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return write_one_page(page, wait);
}

void msg_truncate_setsize(struct inode *inode, loff_t newsize, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_truncate_setsize);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct inode *, loff_t) Argus_type;
    Argus_type argus;
    argus.argu1 = inode;
    argus.argu2 = newsize;
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
    truncate_setsize(inode, newsize);
}

int msg_mapping_tagged(struct address_space *mapping, int tag, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_mapping_tagged);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct address_space *, int) Argus_type;
    Argus_type argus;
    argus.argu1 = mapping;
    argus.argu2 = tag;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return mapping_tagged(mapping, tag);
}

int msg_do_writepages(struct address_space *mapping, struct writeback_control *wbc, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_do_writepages);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct address_space *, struct writeback_control *) Argus_type;
    Argus_type argus;
    argus.argu1 = mapping;
    argus.argu2 = wbc;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return do_writepages(mapping, wbc);
}

int msg_filemap_fdatawait(struct address_space *mapping, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_filemap_fdatawait);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct address_space *) Argus_type;
    Argus_type argus;
    argus.argu1 = mapping;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return filemap_fdatawait(mapping);
}

void msg_truncate_inode_pages(struct address_space *mapping, loff_t lstart, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_truncate_inode_pages);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct address_space *, loff_t) Argus_type;
    Argus_type argus;
    argus.argu1 = mapping;
    argus.argu2 = lstart;
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
    truncate_inode_pages(mapping, lstart);
}

void msg_unregister_shrinker(struct shrinker *shrinker, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_unregister_shrinker);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct shrinker *) Argus_type;
    Argus_type argus;
    argus.argu1 = shrinker;
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
    unregister_shrinker(shrinker);
}

void msg_list_lru_destroy(struct list_lru *lru, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_list_lru_destroy);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct list_lru *) Argus_type;
    Argus_type argus;
    argus.argu1 = lru;
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
    list_lru_destroy(lru);
}



/*
 * 文件系统与内核模块的交互实现
 */
bool msg_capable(int cap, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_capable);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_down_read);
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
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_up_read);
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
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_down_write);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_up_write);
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
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_wake_up_bit);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_bit_waitqueue);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_get_seconds);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_put_pid);
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

int msg_in_group_p(kgid_t grp, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_in_group_p);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(kgid_t) Argus_type;
    Argus_type argus;
    argus.argu1 = grp;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return in_group_p(grp);
}

void msg_yield(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_yield);
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
  } else
    yield();
}

bool msg_inode_capable(const struct inode *inode, int cap, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_inode_capable);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(const struct inode *, int) Argus_type;
    Argus_type argus;
    argus.argu1 = inode;
    argus.argu2 = cap;
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
    return inode_capable(inode, cap);
}

int msg_task_work_add(struct task_struct *task, struct callback_head *twork, bool notify, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_task_work_add);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg3(struct task_struct *, struct callback_head *, bool) Argus_type;
    Argus_type argus;
    argus.argu1 = task;
    argus.argu2 = twork;
    argus.argu3 = notify;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return task_work_add(task, twork, notify);
}

void msg_synchronize_rcu(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_synchronize_rcu);
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
  } else
    synchronize_rcu();
}

void msg_prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_prepare_to_wait);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg3(wait_queue_head_t *, wait_queue_t *, int) Argus_type;
    Argus_type argus;
    argus.argu1 = q;
    argus.argu2 = wait;
    argus.argu3 = state;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    prepare_to_wait(q, wait, state);
}

void msg_schedule(int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_schedule);
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
  } else
    schedule();
}

void msg_finish_wait(wait_queue_head_t *q, wait_queue_t *wait, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_finish_wait);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(wait_queue_head_t *, wait_queue_t *) Argus_type;
    Argus_type argus;
    argus.argu1 = q;
    argus.argu2 = wait;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    finish_wait(q, wait);
}

struct timespec msg_current_fs_time(struct super_block *sb, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_current_fs_time);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct super_block *) Argus_type;
    Argus_type argus;
    argus.argu1 = sb;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    return *(struct timespec *)(sendbuf.object_ptr);
  } else
    return current_fs_time(sb);
}

/*
int msg_lock_is_held(struct lockdep_map *lock, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_lock_is_held);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct lockdep_map *) Argus_type;
    Argus_type argus;
    argus.argu1 = lock;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return lock_is_held(lock);
}
*/

void msg_audit_log_link_denied(const char *operation, struct path *link, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_audit_log_link_denied);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(const char *, struct path *) Argus_type;
    Argus_type argus;
    argus.argu1 = operation;
    argus.argu2 = link;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    audit_log_link_denied(operation, link);
}

int msg_send_sig(int sig, struct task_struct *p, int priv, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_send_sig);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg3(int, struct task_struct *, int) Argus_type;
    Argus_type argus;
    argus.argu1 = sig;
    argus.argu2 = p;
    argus.argu3 = priv;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return send_sig(sig, p, priv);
}

struct timespec msg_timespec_trunc(struct timespec t, unsigned gran, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_timespec_trunc);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg2(struct timespec, unsigned) Argus_type;
    Argus_type argus;
    argus.argu1 = t;
    argus.argu2 = gran;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    return *(struct timespec *)(sendbuf.object_ptr);
  } else
    return timespec_trunc(t, gran);
}

void msg_acct_auto_close_mnt(struct vfsmount *m, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_acct_auto_close_mnt);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct vfsmount *) Argus_type;
    Argus_type argus;
    argus.argu1 = m;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    acct_auto_close_mnt(m);
}

int msg___wait_on_bit(wait_queue_head_t *wq, struct wait_bit_queue *q, int (*action)(void *), unsigned mode, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback___wait_on_bit);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg4(wait_queue_head_t *, struct wait_bit_queue *, action_func_t, unsigned) Argus_type;
    Argus_type argus;
    argus.argu1 = wq;
    argus.argu2 = q;
    argus.argu3 = action;
    argus.argu4 = mode;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
    int ret = *(int *)(sendbuf.object_ptr);
    return ret;
  } else
    return __wait_on_bit(wq, q, action, mode);
}

void msg_free_uid(struct user_struct *up, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_free_uid);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct user_struct *) Argus_type;
    Argus_type argus;
    argus.argu1 = up;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    free_uid(up);
}

void msg_module_put(struct module *module, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_module_put);
    // 创建并初始化参数容器，并将其挂载到消息块中
    typedef Argus_msg1(struct module *) Argus_type;
    Argus_type argus;
    argus.argu1 = module;
    sendbuf.argus_ptr = &argus;
    // 发送消息
    int sendlength, flag;
    sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    flag = my_msgsnd(msqid_from_fs_to_kernel, &sendbuf, sendlength, 0);
    // 阻塞等待接收消息
    flag = my_msgrcv(msqid_from_kernel_to_fs, &sendbuf, sendlength, 3, 0);
    // 处理从kernel传过来的消息
  } else
    module_put(module);
}



/*
 * 文件系统与通用块层的交互实现
 */
void msg_bdevname(struct block_device *bdev, char *buf, int msqid_from_fs_to_kernel, int msqid_from_kernel_to_fs) {
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_bdevname);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_submit_bio);
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
  MY_PRINTK(get_current()->comm);
  if (my_strcmp(get_current()->comm, "fs_kthread") == 0) {
    // 创建并初始化消息块
    struct my_msgbuf sendbuf;
    init_msgbuf(&sendbuf, 3, get_current(), msqid_from_kernel_to_fs, false, callback_put_io_context);
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
