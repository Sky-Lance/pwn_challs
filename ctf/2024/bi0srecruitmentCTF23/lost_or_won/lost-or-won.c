#include <stdio.h>
#include <stdlib.h>

void init()
{
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
}

int win()
{
    printf("Wait thats illegal!!\n");
    printf("You won?\n");
    printf("anyways... take this then\n");
    system("/bin/sh");
    exit(0);
}

int main() 
{
    init();
    printf("Rock paper scissors which one do you pick?\n");
    char buf[64];
    gets(buf);
    printf("You lost ... but can you win?\n");
}