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
    //printk("come in my_memcpyA!\n");
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
    //printk(KERN_INFO "sleep()!\n");
}
// acquire sleep_queue first process

bool isSuccSendB(struct my_msgbuf *sendbuf, int msgsz){

    if(!flagAB){
        // 表示没有足够的内存
        if(msgsendB_begin_addr + (msgsz / 8) > msgrcvA_begin_addr){
            //msgsend_begin_addr = msgsend_begin_addr_tmp;
            return false;
        }
        else{
             // 将消息拷贝到共享内存中，且更新下次发送的首地址
            msgsendB_begin_addr = my_memcpyA(msgsendB_begin_addr, sendbuf, msgsz);
            return true;
        }
    }
    msgsendB_begin_addr = my_memcpyA(msgsendB_begin_addr, sendbuf, msgsz);
    if(msgsendB_begin_addr + (msgsz / 8) > AB_shmAddr + ( maxSize / 8)){
        msgsendB_begin_addr =AB_shmAddr;
        flagAB = false;
        printk(KERN_INFO "the round2 begins : \n");
    }
    return true;
}

void my_msgsendB(struct my_msgbuf *sendbuf, int msgsz){
    // it is not right to send message
    printk("my_msgsendB(): %s\n", get_current()->comm);
    //printk("before: msgsendB_begin_addr = %p\n", msgsendB_begin_addr);
    //printk("msgrcvB_begin_addr = %p\n", msgrcvB_begin_addr); 
    //printk("msgsendA_begin_addr = %p\n", msgsendA_begin_addr); 
    //printk("msgrcvA_begin_addr = %p\n", msgrcvA_begin_addr); 
    while(!isSuccSendB(sendbuf, msgsz)){
        //printk(KERN_INFO "sendB message error!\n");
        //my_sleep(sleeptimes);
    }
    printk("my_msgsendB success!\n");
    //printk("afer: msgsendB_begin_addr = %p\n", msgsendB_begin_addr);
}
EXPORT_SYMBOL(my_msgsendB);

// receive message from fs to kernel
bool isSuccRcvB(struct my_msgbuf *rcvbuf, int msgsz){
    //printk("flagBA = %d, msgrcvB_begin_addr = %p, msgsendA_begin_addr = %p\n", flagBA, msgrcvB_begin_addr, msgsendA_begin_addr);

    if(flagBA && msgrcvB_begin_addr == msgsendA_begin_addr){
        //printk("In isSuccRcvB, return false!\n");
        return false;
    }

    my_memcpyA(rcvbuf, msgrcvB_begin_addr, msgsz);
   //printk(KERN_INFO "after my_memcpy: msgrcv_begin_addr = %p\n", msgrcv_begin_addr);
    my_memsetA(msgrcvB_begin_addr, 0, msgsz);  // 接收完消息后将该段内存清0
   // printk(KERN_INFO "after my_memset: msgrcv_begin_addr = %p\n", msgrcv_begin_addr);

    msgrcvB_begin_addr += (msgsz / 8);  // 更新下次接收消息的首地址
    if(msgrcvB_begin_addr + (msgsz / 8) > BA_shmAddr + (maxSize / 8)){
        msgrcvB_begin_addr = BA_shmAddr;
        flagBA = true;
        printk("In isSuccRcvB, flagBA = %d\n", flagBA);
    }
   // printk(KERN_INFO "after ending: msgrcv_begin_addr = %p\n", msgrcv_begin_addr);

    return true;
}
void my_msgrcvB(struct my_msgbuf *rcvbuf, int msgsz){
    printk("my_msgrcvB(): %s\n", get_current()->comm);
   // printk("msgsendB_begin_addr = %p\n", msgsendB_begin_addr);
    //printk("msgrcvB_begin_addr = %p\n", msgrcvB_begin_addr); 
    //printk("msgsendA_begin_addr = %p\n", msgsendA_begin_addr); 
   // printk("msgrcvA_begin_addr = %p\n", msgrcvA_begin_addr); 
    while(!isSuccRcvB(rcvbuf, msgsz)){
        //printk("come in!\n");
        //my_sleep(sleeptimes);
    }
    printk("my_msgrcvB success!\n");
}
EXPORT_SYMBOL(my_msgrcvB);
