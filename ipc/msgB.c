#include <linux/msgB.h>

unsigned long long *AB_shmAddr;  // from kernel to fs share memory's begin address
EXPORT_SYMBOL(AB_shmAddr);
unsigned long long *msgsendB_begin_addr;  // kernel send message to fs's begin address
EXPORT_SYMBOL(msgsendB_begin_addr);
unsigned long long *msgrcvB_begin_addr; // kernel receive message from fs's begin address
EXPORT_SYMBOL(msgrcvB_begin_addr);

unsigned long long *BA_shmAddr;  // from fs to kernel share memory's begin address
EXPORT_SYMBOL(BA_shmAddr);
unsigned long long *msgsendA_begin_addr;  // fs send message to kernel's begin address
EXPORT_SYMBOL(msgsendA_begin_addr);
unsigned long long *msgrcvA_begin_addr; // fs receive message from kernel's begin address
EXPORT_SYMBOL(msgrcvA_begin_addr);
int maxSize = 1024;  // share memory's size
EXPORT_SYMBOL(maxSize);
bool flagAB = true;  // kernel to fs, kernel send message address > fs receive message address
EXPORT_SYMBOL(flagAB);
bool flagBA = true;  // fs to kernel, fs send message address >· kernel receive message address
EXPORT_SYMBOL(flagBA);

void *my_memcpyB(void *v_dst, const void *v_src, long unsigned int c)
{
	const char *src = v_src;
	char *dst = v_dst;

	/* Simple, byte oriented memcpy. */
	while (c--)
		*dst++ = *src++;

	return dst;
}
void *my_memsetB(void *s, int c, long unsigned int n)
{
	int i;
	char *ss = s;

	for (i = 0; i < n; i++)
		ss[i] = c;
	return s;
}
void init_shm(){
    msgsendA_begin_addr = BA_shmAddr;
    msgrcvA_begin_addr = AB_shmAddr;

    msgsendB_begin_addr = AB_shmAddr;
    msgrcvB_begin_addr = BA_shmAddr;
}
EXPORT_SYMBOL(init_shm);

bool isSuccSendA(struct my_msgbuf *sendbuf, int msgsz){
    if(!flagBA){
        if(msgsendA_begin_addr + (msgsz / 8) > msgrcvB_begin_addr)
            return false;
        else{
            msgsendA_begin_addr = my_memcpyB(msgsendA_begin_addr, sendbuf, msgsz);
            return true;
        }
    }
    msgsendA_begin_addr = my_memcpyB(msgsendA_begin_addr, sendbuf, msgsz);
    
    if(msgsendA_begin_addr + (msgsz / 8) > BA_shmAddr + ( maxSize / 8)){
        msgsendA_begin_addr = BA_shmAddr;
        flagBA = false;
    }
    
    return true;

} 
void my_msgsendA(struct my_msgbuf *sendbuf, int msgsz){
    printk("my_msgsendA(): %s\n", get_current()->comm);
    //printk("msgsendB_begin_addr = %p\n", msgsendB_begin_addr);
    //printk("msgrcvB_begin_addr = %p\n", msgrcvB_begin_addr); 
    //printk("msgsendA_begin_addr = %p\n", msgsendA_begin_addr); 
   // printk("msgrcvA_begin_addr = %p\n", msgrcvA_begin_addr); 
  while(!isSuccSendA(sendbuf, msgsz)){
         //printk(KERN_INFO "sendA message is error!\n");
    }
    printk("my_msgsendA success\n");

}
EXPORT_SYMBOL(my_msgsendA);

bool isSuccRcvA(struct my_msgbuf *rcvbuf, int msgsz){
    //unsigned long long *msgrcv_begin_addr_tmp = msgrcv_begin_addr;
    /*
    if(msgrcvA_begin_addr + (msgsz / 8) > AB_shmAddr + (maxSize / 8)){
        msgrcvA_begin_addr = AB_shmAddr;
        flagAB = true;
    }
    */
    if(flagAB && msgrcvA_begin_addr == msgsendB_begin_addr){

        return false;
    }

    my_memcpyB(rcvbuf, msgrcvA_begin_addr, msgsz);    
    my_memsetB(msgrcvA_begin_addr, 0, msgsz);
    msgrcvA_begin_addr += (msgsz / 8);
    if(msgrcvA_begin_addr + (msgsz / 8) > AB_shmAddr + (maxSize / 8)){
        msgrcvA_begin_addr = AB_shmAddr;
        flagAB = true;
    }
    return true;
}
void my_msgrcvA(struct my_msgbuf *rcvbuf, int msgsz){
    printk("my_msgrcvA(): %s\n", get_current()->comm);
    //printk("before: msgsendB_begin_addr = %p\n", msgsendB_begin_addr);
    //printk("msgrcvB_begin_addr = %p\n", msgrcvB_begin_addr); 
   // printk("msgsendA_begin_addr = %p\n", msgsendA_begin_addr); 
    //printk("before: msgrcvA_begin_addr = %p\n", msgrcvA_begin_addr); 
    while(!isSuccRcvA(rcvbuf, msgsz)){
        //printk(KERN_INFO "receiveA message error!\n"); 
    }
     //printk("afer: msgsendB_begin_addr = %p\n", msgsendB_begin_addr);
     //printk("afer: msgrcvA_begin_addr = %p\n", msgrcvA_begin_addr);
    printk(" my_msgrcvA success\n");
}
EXPORT_SYMBOL(my_msgrcvA);
