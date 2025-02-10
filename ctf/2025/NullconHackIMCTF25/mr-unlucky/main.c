#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const char *heroes[] = {
    "Anti-Mage", "Axe", "Bane", "Bloodseeker", "Crystal Maiden",
    "Drow Ranger", "Earthshaker", "Juggernaut", "Mirana", "Morphling",
    "Phantom Assassin", "Pudge", "Shadow Fiend", "Sniper", "Storm Spirit",
    "Sven", "Tiny", "Vengeful Spirit", "Windranger", "Zeus"
};

int main() {
    time_t current_time;
    current_time = time(NULL);
    srand(current_time);

    for (int i = 0; i < 0x32; i++) {
        int hero_index = rand() % 20;
        printf("%s\n", heroes[hero_index]); 
    }

    return 0;
}
