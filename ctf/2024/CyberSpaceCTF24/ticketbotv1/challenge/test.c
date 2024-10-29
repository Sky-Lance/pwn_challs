#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned int ticket1 = 2095833048;
    unsigned int ticket2 = 2113922313;
    unsigned int ticket3 = 2050920210;
    
    for (unsigned int seed = 0; seed < 10000000; seed++) {
        srand(seed);
        rand();
        if (rand() == ticket1 && rand() == ticket2 && rand() == ticket3) {
            printf("Found seed: %u\n", seed);
            srand(seed);
            unsigned int password = rand();
            printf("Password is: %u\n", password);
            break;
        }
    }
    
    return 0;
}
