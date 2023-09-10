#include <stdio.h>

__asm__(
  "pop %rdi\n"
  "pop %rsi\n"
  "ret"
  );

void init(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    alarm(60);
}

void banner(){
    puts("---------------------------------------------------------------");
    puts("                                  )___(");
    puts("                           _______/__/_");
    puts("                  ___     /===========|   ___");
    puts(" ____       __   [\\\\\\]___/____________|__[///]   __");
    puts(" \\   \\_____[\\\\]__/___________________________\\__[//]___");
    puts("  \\1337                                                |");
    puts("   \\                                                  /");
    puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    puts("---------------------------------------------------------------");
    puts("Jeff: Captain, we've got a wild sea monster ahead, and it insists on playing rock-paper-scissors with us! If we lose, it's game over.");
    puts("Jeff: You're our fearless leader, Captain. Show us the way to conquer this challenge and lead us to victory!");
    puts("---------------------------------------------------------------");
}

int main(){
    init();
    banner();
    int ch;
    puts("* Start playing the game: 1\n* Get a powerup before playing the game: 2");
    scanf("%d", &ch);
    
    if(ch == 2){
        printf("get this powerup and win against the monster: %p\n", &main);
    }

    char choice[8];
    puts("---------------------------------------------------------------");
    puts("1 : rock\n2 : paper\n3 : scissors");
    puts("Choice :");
    getchar();
    gets(choice);
    puts("Monster: You humans are no match to my super-monster game skills. You will loose everytime.");
}