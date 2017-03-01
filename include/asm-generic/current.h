#ifndef __ASM_GENERIC_CURRENT_H
#define __ASM_GENERIC_CURRENT_H

#include <linux/thread_info.h>
// #include <linux/sched.h>
// #include <linux/interactive_design.h>
// #include <linux/msg_xxx.h.h>

struct task_struct;

// extern struct task_struct *fs_temp;
// extern bool fs_start;

#define get_current() (current_thread_info()->task)

#define current get_current()
// #define current ((my_strcmp_base(get_current()->comm, "fs_kthread") == 0 && fs_start) ? fs_temp : get_current())

#endif /* __ASM_GENERIC_CURRENT_H */
