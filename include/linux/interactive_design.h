#ifndef _INTERACTIVE_DESIGN_H
#define _INTERACTIVE_DESIGN_H

#include<linux/my_msg.h>

static int my_strcmp(const char *cs, const char *ct) {
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

#define MY_PRINTK(info)                                                 \
  if (my_strcmp(current->comm, "fs_kthread") == 0 || my_strcmp(current->comm, "kernel_kthread") == 0)	\
    printk("FILE = %s, LINE = %d, FUNC = %s, current->comm = %s\n", __FILE__, __LINE__, __FUNCTION__, info)

#define SEND_TIME 100000
#define PATH_SIZE 128

#define typeof __typeof__

#define Pointer(T) typeof(T *)
#define Array(T, N) typeof(T [N])

#define Func_msg0(functype)                     \
    struct Func_container2 {                    \
        functype funcptr;                       \
    }

#define Func_msg1(functype, type1)              \
    struct Func_container2 {                    \
        functype funcptr;                       \
        type1 argu1;                            \
    }

#define Func_msg2(functype, type1, type2)       \
    struct Func_container2 {                    \
        functype funcptr;                       \
        type1 argu1;                            \
        type2 argu2;                            \
    }

#define Func_msg3(functype, type1, type2, type3)  \
    struct Func_container3 {                      \
        functype funcptr;                         \
        type1 argu1;                              \
        type2 argu2;                              \
        type3 argu3;                              \
    }

#define Func_msg4(functype, type1, type2, type3, type4) \
    struct Func_container4 {                            \
        functype funcptr;                               \
        type1 argu1;                                    \
        type2 argu2;                                    \
        type3 argu3;                                    \
        type4 argu4;                                    \
    }

#define Func_msg5(functype, type1, type2, type3, type4, type5)  \
    struct Func_container5 {                                    \
        functype funcptr;                                       \
        type1 argu1;                                            \
        type2 argu2;                                            \
        type3 argu3;                                            \
        type4 argu4;                                            \
        type5 argu5;                                            \
    }

#define Func_msg6(functype, type1, type2, type3, type4, type5, type6) \
    struct Func_container6 {                                          \
        functype funcptr;                                             \
        type1 argu1;                                                  \
        type2 argu2;                                                  \
        type3 argu3;                                                  \
        type4 argu4;                                                  \
        type5 argu5;                                                  \
        type6 argu6;                                                  \
    }

static int msqid_from_kernel_to_fs = -1;
static int msqid_from_fs_to_kernel = -1;
// static struct task_struct *tsk = NULL;

#endif
