#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void init(){
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(60);
}

int main(){
    init();
    char arr[64];
    int target = 0xdeadbeef;
    puts("Wanna say something ?");
    gets(arr);
    if(target == 0xcafebabe){
        system("/bin/sh\x00");
    }
}