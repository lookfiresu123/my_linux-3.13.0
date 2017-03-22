#ifndef __LINUX_MSGB_H
#define __LINUX_MSGB_H

#include<linux/sched.h>
extern unsigned long long *AB_shmAddr;  
extern unsigned long long *BA_shmAddr;  
extern unsigned long long *msgsendB_begin_addr;  
extern unsigned long long *msgrcvB_begin_addr; 
extern unsigned long long *msgsendA_begin_addr;  
extern unsigned long long *msgrcvA_begin_addr; 
extern int maxSize;
extern bool flagAB;
extern bool flagBA;
/*
struct my_msgbufAB {
    //long mtype;
    //char mtext[1];
    char mtext[128];
};
struct my_msgbufBA {
    //long mtype;
    //char mtext[1];
    char mtext[128];
};
*/


struct my_msgbuf {
  //long mtype;
  //char mtext[1];
  struct task_struct *tsk;
  void (*callback)(struct my_msgbuf *msgp);                 // 需要在初始化时注册处理函数，用于让接收方或发送方调用并处理该消息中的data_ptr
  void *argus_ptr;// 泛型指针，用于存储任意数量和类型的实参
  void *object_ptr;// 泛型指针，用于存储任意类型的返回值
  bool isend;// 结束为1，否则为0
  int msqid;//回调函数会将消息发送到这个消息队列中
};

void init_shm(void);
void my_msgsendA(struct my_msgbuf *, int);
void my_msgrcvA(struct my_msgbuf *, int);
void *my_memcpyB(void *v_dst, const void *v_src, long unsigned int c);
void *my_memsetB(void *s, int c, long unsigned int n);
bool isSuccSendA(struct my_msgbuf *, int);
bool isSuccRcvA(struct my_msgbuf*, int);

#endif