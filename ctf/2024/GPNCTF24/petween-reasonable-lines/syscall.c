#include <stdio.h>

int main() {
    const char *t = "Hello, World!";
    syscall(1, 1, t, 14);
    return 0;
}
