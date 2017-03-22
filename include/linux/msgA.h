#ifndef __LINUX_MSGA_H
#define __LINUX_MSGA_H

#include "msgB.h"
void my_msgsendB(struct my_msgbuf *, int);
void my_msgrcvB(struct my_msgbuf *, int);
void *my_memcpyA(void *v_dst, const void *v_src, long unsigned int c);
void *my_memsetA(void *s, int c, long unsigned int n);
void my_sleep(unsigned sec);
bool isSuccSendB(struct my_msgbuf *, int);
bool isSuccRcvB(struct my_msgbuf *, int);

#endif