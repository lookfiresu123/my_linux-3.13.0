#include <linux/sched.h>
#include <linux/msgA.h>


/*
when kernel send message to fs or receive message from fs, the share memory area might be full or empty.
the process is sleeping.sleeptimes is the process sleep times.
*/
int sleeptimes = 1;
EXPORT_SYMBOL(sleeptimes);

void *my_memcpyA(void *v_dst, const void *v_src, long unsigned int c)
{
	const char *src = v_src;
	char *dst = v_dst;

	/* Simple, byte oriented memcpy. */
	while (c--)
		*dst++ = *src++;

	return dst;
}
void *my_memsetA(void *s, int c, long unsigned int n)
{
	int i;
	char *ss = s;

	for (i = 0; i < n; i++)
		ss[i] = c;
	return s;
}
void my_sleep(unsigned sec){
    current->state = TASK_INTERRUPTIBLE;
    schedule_timeout(sec * 10);
}
// acquire sleep_queue first process

bool isSuccSendB(struct my_msgbuf *sendbuf, int msgsz){

    if(!flagAB){
        if(msgsendB_begin_addr + (msgsz / 8) > msgrcvA_begin_addr){
            return false;
        }
        else{
            msgsendB_begin_addr = my_memcpyA(msgsendB_begin_addr, sendbuf, msgsz);
            return true;
        }
    }
    msgsendB_begin_addr = my_memcpyA(msgsendB_begin_addr, sendbuf, msgsz);
    if(msgsendB_begin_addr + (msgsz / 8) > AB_shmAddr + ( maxSize / 8)){
        msgsendB_begin_addr =AB_shmAddr;
        flagAB = false;
        //printk(KERN_INFO "the round2 begins : \n");
    }
    return true;
}

void my_msgsendB(struct my_msgbuf *sendbuf, int msgsz){
    // it is not right to send message
    //printk("my_msgsendB(): %s\n", get_current()->comm);
    while(!isSuccSendB(sendbuf, msgsz)){
    }
    //printk("my_msgsendB success!\n");
}
EXPORT_SYMBOL(my_msgsendB);

// receive message from fs to kernel
bool isSuccRcvB(struct my_msgbuf *rcvbuf, int msgsz){

    if(flagBA && msgrcvB_begin_addr == msgsendA_begin_addr){
        return false;
    }

    my_memcpyA(rcvbuf, msgrcvB_begin_addr, msgsz);
    my_memsetA(msgrcvB_begin_addr, 0, msgsz);

    msgrcvB_begin_addr += (msgsz / 8);
    if(msgrcvB_begin_addr + (msgsz / 8) > BA_shmAddr + (maxSize / 8)){
        msgrcvB_begin_addr = BA_shmAddr;
        flagBA = true;
        //printk("In isSuccRcvB, flagBA = %d\n", flagBA);
    }

    return true;
}
void my_msgrcvB(struct my_msgbuf *rcvbuf, int msgsz){
    //printk("my_msgrcvB(): %s\n", get_current()->comm);
    while(!isSuccRcvB(rcvbuf, msgsz)){
    }
    //printk("my_msgrcvB success!\n");
}
EXPORT_SYMBOL(my_msgrcvB);
