#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    char shellcode[1024]; // Buffer to hold the shellcode input
    size_t shellcode_len; // Length of shellcode

    // Read shellcode from user
    printf("Enter the length of your shellcode (in bytes): ");
    if (scanf("%zu", &shellcode_len) != 1 || shellcode_len > sizeof(shellcode)) {
        fprintf(stderr, "Invalid length or length too large.\n");
        return 1;
    }
    
    // Consume newline left by scanf
    getchar();

    printf("Enter your shellcode (raw binary input):\n");

    // Read raw binary data
    if (fread(shellcode, 1, shellcode_len, stdin) != shellcode_len) {
        perror("fread");
        return 1;
    }

    // Allocate memory for shellcode and copy it there
    void *mem = mmap(NULL, shellcode_len, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    memcpy(mem, shellcode, shellcode_len);

    // Cast the memory to function pointer and execute it
    void (*exec_shellcode)() = (void (*)())mem;
    exec_shellcode();

    // Clean up
    munmap(mem, shellcode_len);

    return 0;
}
