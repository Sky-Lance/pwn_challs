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
        return remote("20.244.40.210", 6000)
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
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

output = subprocess.check_output(["./main"], text=True).strip()
hero_list = output.split("\n")
print(hero_list)
for i in range(len(hero_list)):
    if hero_list[i] == "Polvor":
        hero_list[i] = "Polvor\xc3\xb3n"
    if hero_list[i] == "Pfeffern":
        hero_list[i] = "Polvor\xc3\xb3sse"
    sla(b"Guess the cookie: ", hero_list[i])

io.interactive()
