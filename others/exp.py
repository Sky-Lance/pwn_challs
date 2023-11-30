from pwn import *

io = process("./cmubomb")
io = gdb.debug("./cmubomb", 
'''
set disassembly-flavor intel

display/x $eax
display/x $ebx
display/x $ecx
display/x $edx
display/x $edi
display/x $ebp-0x38
display/x $esi
continue
''')
#io = remote("15.206.149.154", 30012)
context.log_level = 'debug' 

io.recvuntil("nice day!\n")
io.sendline('Public speaking is very easy.')
io.recvuntil("xt one?\n")
io.sendline("1 2 6 24 120 720")
io.recvuntil("oing!\n")
io.sendline("5 t 458")
io.recvuntil("here!\n")
io.sendline("9 a")
io.recvuntil("his one.\n")
io.sendline('opekma')
io.recvuntil("next...\n")
io.sendline('4 2 6 3 1 5')
io.interactive()

'''
break *0x08048dc7
break *0x08048dd4
break *0x08048dec
break *0x08048df7
break *0x08048dfd
break *0x08048e21
break *0x08048e34
break *0x08048e3f
break *0x08048e5b
break *0x08048e75
break *0x08048e82
'''