#ifndef __LINUX_MSGA_SYNC_H
#define __LINUX_MSGA_SYNC_H

#include <linux/msgA.h>
extern wait_queue_head_t head;

extern wait_queue_t *curr;

extern int processNum;
extern spinlock_t procNum;
extern spinlock_t shmArea;

struct task_struct* acqNextProc(void);
void wakeupProc(void);
bool isAddWaitQueue(wait_queue_t *data, struct task_struct *);
void wakeupProc(void);
void AreceiveB(struct my_msgbuf *, int);
void AsendB(struct my_msgbuf *, int);
void init_waitqueue(void);

#endif