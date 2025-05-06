#include <stdio.h>
#include <stdint.h>
#include <string.h> 

int main() {
    uint64_t target = 0x80492c000000000;

    uint64_t combined = (uint64_t)target; 
    double d;
    memcpy(&d, &combined, sizeof(d)); 

    printf("%.16e\n", d);

    return 0;
}