#include <stdio.h>
#include <sys/mman.h>

void init()
{
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
}

int main() 
{
    init();
    printf("The perfect code is short and easy to understand, Give me a byte sized code \n...(maybe few bytes)==>\n");
    int *shellcod = (int *)(0x404000);
    mprotect(shellcod,0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
    
    gets(shellcod);
    
    int (*ret)() = (int (*)())shellcod;
    ret();
    printf("Shellcode executed succesfully ... Hope you got a shell? But if you did you probably wouldnt see this");
}