#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/msgA.h>


//struct task_struct *watchDog;
//EXPORT_SYMBOL(watchDog);
struct task_struct *nexttsk;
EXPORT_SYMBOL(nexttsk);

wait_queue_head_t head;
EXPORT_SYMBOL(head);

//wait_queue_t *curr;
//EXPORT_SYMBOL(curr);

int processNum = 0;
EXPORT_SYMBOL(processNum);

DEFINE_SPINLOCK(procNum);
EXPORT_SYMBOL(procNum);
DEFINE_SPINLOCK(shmArea);
EXPORT_SYMBOL(shmArea);

void init_waitqueue(void){
	init_waitqueue_head(&head);
}
EXPORT_SYMBOL(init_waitqueue);

struct task_struct* acqNextProc(void){
    wait_queue_t *curr = list_first_entry(&(head.task_list), typeof(*curr), task_list);
    nexttsk = (struct task_struct *)(curr->private);
    return nexttsk;
}
bool isAddWaitQueue(wait_queue_t *data, struct task_struct *tsk){
	
	//printk(KERN_INFO "1: head addr is %p, data addr is %p, current is %p\n", &head, &data, tsk);

	init_waitqueue_entry(data, tsk);

	//printk(KERN_INFO "2: head addr is %p, data addr is %p, current is %p\n", &head, &data, tsk);
	
	add_wait_queue_exclusive(&head, data);

	spin_lock(&procNum);
	processNum ++;		
	// it means not only self is in sleep queue;
	
	if(processNum > 1){
		spin_unlock(&procNum);
		prepare_to_wait(&head, data, TASK_INTERRUPTIBLE);
		return true;
	}
	spin_unlock(&procNum);
	prepare_to_wait(&head, data, TASK_INTERRUPTIBLE);
	finish_wait(&head, data);
	return false;
}

void wakeupProc(void){
	//printk(KERN_INFO "other process is interruptible and i will wake up it!\n");
	acqNextProc();		
	int a = wake_up_process(nexttsk);
	//printk(KERN_INFO "my_fun2():wake_up_process returns %d, process->comm is %s\n", a, nexttsk->comm);
}
void AreceiveB(struct my_msgbuf *rcvbuf, int msgsz){

	my_msgrcvB(rcvbuf, msgsz);
	spin_lock(&procNum);
	processNum--;
	if(processNum > 0){
		spin_unlock(&procNum);
		wakeupProc();
	}
	else
		spin_unlock(&procNum);
}
EXPORT_SYMBOL(AreceiveB);

void AsendB(struct my_msgbuf *sendbuf, int msgsz){
	struct task_struct *tmp_tsk = current;
	//printk(KERN_INFO "In AsendB: head addr = %p, current  = %s, and addr  = %p\n", &head, current->comm, current);
	spin_lock(&shmArea);
	my_msgsendB(sendbuf, msgsz);
	spin_unlock(&shmArea);
	//printk(KERN_INFO "In AsendB: current  = %s, and addr  = %p\n", current->comm, current);
	//printk(KERN_INFO "before: head addr is %p,  current is %p\n", &head,  tmp_tsk);
	wait_queue_t data;
	//printk(KERN_INFO "before : head addr is %p, data addr = %p\n", &head, &data);
	bool res = isAddWaitQueue(&data, tmp_tsk);
	//printk(KERN_INFO "after: head addr is %p, data addr is %p, current is %p\n", &head, &data, tmp_tsk);
	struct task_struct *data_private = (struct task_struct *)(&data.private);
	//printk(KERN_INFO "and data.private = %p\n", &data.private);
	if(res){
		schedule();
		finish_wait(&head, &data);
	}
}
EXPORT_SYMBOL(AsendB);