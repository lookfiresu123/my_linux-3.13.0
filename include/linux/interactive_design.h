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
    printk("%s(): %s\n", __FUNCTION__, info)

#define MY_DUMP_STACK()                                                 \
  if (my_strcmp(current->comm, "fs_kthread") == 0 || my_strcmp(current->comm, "kernel_kthread") == 0) \
    dump_stack()


#define SEND_TIME 100000
#define PATH_SIZE 128

#define typeof __typeof__

#define Pointer(T) typeof(T *)
#define Array(T, N) typeof(T [N])

#define Argus_msg0()                             \
    struct Argus_container0 {                    \
    }

#define Argus_msg1(type1)                        \
    struct Argus_container1 {                    \
      type1 argu1;                               \
    }

#define Argus_msg2(type1, type2)                 \
    struct Argus_container2 {                    \
      type1 argu1;                               \
      type2 argu2;                               \
    }

#define Argus_msg3(type1, type2, type3)            \
    struct Argus_container3 {                      \
      type1 argu1;                                 \
      type2 argu2;                                 \
      type3 argu3;                                 \
    }

#define Argus_msg4(type1, type2, type3, type4)           \
    struct Argus_container4 {                            \
      type1 argu1;                                       \
      type2 argu2;                                       \
      type3 argu3;                                       \
      type4 argu4;                                       \
    }

#define Argus_msg5(type1, type2, type3, type4, type5)            \
    struct Argus_container5 {                                    \
      type1 argu1;                                               \
      type2 argu2;                                               \
      type3 argu3;                                               \
      type4 argu4;                                               \
      type5 argu5;                                               \
    }

#define Argus_msg6(type1, type2, type3, type4, type5, type6)           \
    struct Argus_container6 {                                          \
      type1 argu1;                                                     \
      type2 argu2;                                                     \
      type3 argu3;                                                     \
      type4 argu4;                                                     \
      type5 argu5;                                                     \
      type6 argu6;                                                     \
    }



extern int msqid_from_kernel_to_fs;
extern int msqid_from_fs_to_kernel;
// static struct task_struct *tsk = NULL;

#endif
