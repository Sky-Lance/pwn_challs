#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/resource.h>

int main() {
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child process
        printf("Child process (PID: %d) running...\n", getpid());
        sleep(2);  // Simulate some work
        printf("Child process (PID: %d) exiting...\n", getpid());
        return 42;  // Exit with a status code
    } else {
        // Parent process
        int status;
        struct rusage usage;
        pid_t waited_pid = wait4(pid, &status, 0, &usage);

        if (waited_pid == -1) {
            perror("wait4");
            return 1;
        }

        printf("Parent: Child %d terminated.\n", waited_pid);
        
        if (WIFEXITED(status)) {
            printf("Exit status: %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Killed by signal: %d\n", WTERMSIG(status));
        }

        printf("User time: %ld.%06ld sec\n", 
               (long)usage.ru_utime.tv_sec, (long)usage.ru_utime.tv_usec);
        printf("System time: %ld.%06ld sec\n", 
               (long)usage.ru_stime.tv_sec, (long)usage.ru_stime.tv_usec);
    }

    return 0;
}
