#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H

#include <linux/compiler.h>
#include <asm/percpu.h>
// #include <linux/sched.h>
// #include <linux/interactive_design.h>

#ifndef __ASSEMBLY__
struct task_struct;

// extern struct task_struct *fs_temp;
// extern bool fs_start;

DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
	return this_cpu_read_stable(current_task);
}

static int my_strcmp_base(const char *cs, const char *ct) {
	unsigned char c1, c2;

	while (1) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}

#define current get_current()
// #define current ((my_strcmp_base(get_current()->comm, "fs_kthread") == 0 && fs_start) ? fs_temp : get_current())

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CURRENT_H */
