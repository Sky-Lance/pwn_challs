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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *parse_line
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

payload = b''

def add(val):
    global payload
    payload += f"ADD {val}\n".encode()
    
def mul(val):
    global payload
    payload += f"TIMES {val}\n".encode()
    
def disp():
    global payload
    payload += f"PRINT\n".encode()

def startif():
    global payload
    payload += f"IF\n".encode()

def endif():
    global payload
    payload += f"ENDIF\n".encode()

add(5)
disp()
mul(3)
# disp()
add(2)
disp()

sla(b"Code:", payload)
io.interactive()
