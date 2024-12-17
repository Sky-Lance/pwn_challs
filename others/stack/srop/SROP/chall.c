#include <stdio.h>
#include <stdlib.h>

void syscall_(){
       __asm__("syscall; ret;");
}

void set_rax(){
       __asm__("movl $0xf, %eax; ret;");
}

int main(){
       // ONLY SROP!
       char buff[100];
       printf("Buff @%p, can you SROP?\n", buff);
       read(0, buff, 5000);
       return 0;
}